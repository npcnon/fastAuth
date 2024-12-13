from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Header, Query, Request, status, Response
import httpx
from sqlalchemy.orm import Session
from app.crud.api_keys import create_api_key, validate_api_key
from app.database import get_db
from app.models.user import UserRole
from app.schemas.user import UserCreate, UserLogin, UserResponse
from app.crud.jti import create_blocked_jti, get_hashed_jti
from app.exceptions import DataMismatchException, BlockedAccessTokenException, BlockedRefreshTokenException
from app.crud.user import change_password, get_all_users, get_user_by_email_or_username, create_user, authenticate_user
from app.utils.security import create_access_token, create_refresh_token, decode_tokens
import os
from dotenv import load_dotenv
from app.utils import requests
from jose import jwt
from typing import List
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
CLIENT_API_URL=os.getenv("CLIENT_API_URL")
ALGORITHM = "HS256"

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(request: Request,user: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user with moderator authorization.

    This endpoint handles user registration with comprehensive validation:
    - Requires moderator authentication
    - Checks for existing users
    - Validates employee details from external API
    - Processes and assigns user roles
    - Creates user account

    Parameters:
    - `request`: The incoming HTTP request containing moderator access token.
    - `user`: UserCreate object with registration details (username, email, password, identifier).
    - `db`: Database session dependency for user creation and validation.

    Returns:
    - Newly created user object with assigned details and roles.

    Registration Process:
    1. Validate moderator access token
    2. Check for existing user with same username or email
    3. Fetch employee details from external API
    4. Validate and normalize employee roles
    5. Create user account with assigned roles

    Raises:
    - `HTTPException(400)`:
        - If user already exists
        - If employee account is not active
        - If invalid roles are detected
    - `HTTPException(405)`: If the requester is not a moderator
    - `HTTPException(503)`: If external employee API is unavailable

    Role Processing:
    - Normalizes roles (lowercase)
    - Converts API roles to predefined user roles
    - Handles multiple role assignments

    Available Roles:
    - MODERATOR
    - ADMIN
    - SUPERADMIN
    - MIS
    - DATACENTER
    - PROFESSOR
    - INSTRUCTOR
    - DEAN
    - ACCOUNTING
    - REGISTRAR

    Security Measures:
    - Moderator-only registration
    - External API employee verification
    - Role validation
    - Prevents duplicate user creation
    """
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=405, detail="only moderators can create api tokens")

    decoded_access_token = decode_tokens(access_token)
    if "mod" not in decoded_access_token or not decoded_access_token.get("mod"):
        raise HTTPException(status_code=405, detail="only moderators can create api tokens")
    
    db_user = get_user_by_email_or_username(db, user.username, user.email)
    if db_user:
        # print(f"dbuser: {db_user}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")
    
    try:
        employee_details = await requests.fetch_public_employee_data(CLIENT_API_URL, user.identifier)
        
        if employee_details is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Employee account is not active"
            )
        
        api_roles = employee_details.get('role', '').split(',')  # Split roles by comma
        api_roles = [role.strip().lower() for role in api_roles]  # Normalize role names (lowercase)

        assigned_roles = []

        for api_role in api_roles:
            try:
                assigned_roles.append(UserRole(api_role).value)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid role '{api_role}' found for this user"
                )

        
        return create_user(
            db, 
            username=user.username, 
            email=user.email, 
            password=user.password, 
            role=assigned_roles,
            identifier=user.identifier
        )
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=str(e)
        )
    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail="External API is unavailable"
        )
    
@router.post("/grading-login")
async def grading_login(request: Request,user: UserLogin, response: Response, db: Session = Depends(get_db), api_key: str = Header(alias="X-API-Key")):
    """
    Authenticate and log in users for Grading-related services.

    This endpoint handles login for users with specific administrative roles:
    - Requires a valid grading service API key
    - Authenticates user credentials
    - Validates user role (Dean, Admin)
    - Generates access and refresh tokens

    Parameters:
    - `user`: UserLogin object containing username and password.
    - `response`: HTTP response object for setting authentication cookies.
    - `db`: Database session dependency for user authentication.
    - `api_key`: API key header (X-API-Key) for service authentication.

    Returns:
    - A dictionary containing:
        - Login success message
        - User subject (username)
        - User details from the MIS system

    Authentication Process:
    1. Validate grading service API key
    2. Authenticate user credentials
    3. Fetch and verify employee details
    4. Check user role eligibility
    5. Generate access and refresh tokens
    6. Set secure HTTP-only cookies

    Raises:
    - `HTTPException(403)`: If the provided API key is invalid or expired
    - `HTTPException(405)`: If the user's role is not authorized 
      (not Instructor, Professor, Admin, Registrar)

    Allowed Roles:
    - Instructor
    - Professor
    - Admin
    - Registrar

    Security Measures:
    - API key validation
    - Role-based access control
    - Secure token generation
    - HTTP-only, secure cookies
    """
    if not validate_api_key(api_key=api_key, expected_service='grading', db=db):
        raise HTTPException(
            status_code=403, 
            detail="Invalid or expired API Key for Grading Service"
        )
    
    db_user = authenticate_user(db, user.username, user.password)
    employee_details = await requests.fetch_public_employee_data(f"{CLIENT_API_URL}?", db_user.identifier)
    
    # print(f"is it a professor/instructor? {any(role in employee_details.get("role", "") for role in ["Instructor", "Professor"])}")
    if not any(role in employee_details.get("role", "") for role in ["Instructor", "Professor","Admin","Registrar"]):
        raise HTTPException(status_code=405, detail="Role must include either 'Instructor' ,'Professor', 'Admin', 'Registrar'")
    
    
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    if access_token:
        response.delete_cookie("access_token")
    if refresh_token:
        response.delete_cookie("refresh_token")
    
    # print(f"role: {employee_details["role"]}")
    access_token = create_access_token(data={
        "sub": db_user.username,
        "user_details": employee_details
        })
    refresh_token = create_refresh_token(data={"sub": db_user.username})
    
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True,  
        secure=True,    
        samesite="None"
    )
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token, 
        httponly=True,
        secure=True,
        samesite="None"
    )

    return {"message": "Login successful",
            "sub": db_user.username,
            "user_details": employee_details
            }


@router.post("/scheduling-login")
async def scheduling_login(request: Request,user: UserLogin, response: Response, db: Session = Depends(get_db), api_key: str = Header(alias="X-API-Key")):
    """
    Authenticate and log in users for SCHEDULING-related services.

    This endpoint handles login for users with specific administrative roles:
    - Requires a valid scheduling service API key
    - Authenticates user credentials
    - Validates user role (Dean, Admin)
    - Generates access and refresh tokens

    Parameters:
    - `user`: UserLogin object containing username and password.
    - `response`: HTTP response object for setting authentication cookies.
    - `db`: Database session dependency for user authentication.
    - `api_key`: API key header (X-API-Key) for service authentication.

    Returns:
    - A dictionary containing:
        - Login success message
        - User subject (username)
        - User details from the MIS system

    Authentication Process:
    1. Validate Scheduling service API key
    2. Authenticate user credentials
    3. Fetch and verify employee details
    4. Check user role eligibility
    5. Generate access and refresh tokens
    6. Set secure HTTP-only cookies

    Raises:
    - `HTTPException(403)`: If the provided API key is invalid or expired
    - `HTTPException(405)`: If the user's role is not authorized 
      (not Dean or Admin)

    Allowed Roles:
    - Dean
    - Admin

    Security Measures:
    - API key validation
    - Role-based access control
    - Secure token generation
    - HTTP-only, secure cookies
    """
    if not validate_api_key(api_key=api_key, expected_service='scheduling', db=db):
        raise HTTPException(
            status_code=403, 
            detail="Invalid or expired API Key for Scheduling Service"
        )
    
    db_user = authenticate_user(db, user.username, user.password)
    employee_details = await requests.fetch_public_employee_data(f"{CLIENT_API_URL}?", db_user.identifier)
    
    if not any(role in employee_details.get("role", "") for role in ["Dean","Admin",]):
        raise HTTPException(status_code=405, detail="Role must include either 'Dean', 'Admin'")
    
    
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    if access_token:
        response.delete_cookie("access_token")
    if refresh_token:
        response.delete_cookie("refresh_token")
    
    # print(f"role: {employee_details["role"]}")
    access_token = create_access_token(data={
        "sub": db_user.username,
        "user_details": employee_details
        })
    refresh_token = create_refresh_token(data={"sub": db_user.username})
    
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True,  
        secure=True,    
        samesite="None"
    )
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token, 
        httponly=True,
        secure=True,
        samesite="None"
    )

    return {"message": "Login successful",
            "sub": db_user.username,
            "user_details": employee_details
            }

@router.post("/portal-login")
async def portal_login(request: Request,user: UserLogin, response: Response, db: Session = Depends(get_db), api_key: str = Header(alias="X-API-Key")):
    """
    Authenticate and log in registrar users for portal access.

    This endpoint handles login specifically for registrar users:
    - Requires a valid Portal service API key
    - Authenticates user credentials
    - Fetches and validates employee details
    - Ensures only registrar users can access
    - Generates access and refresh tokens
    - Manages existing authentication cookies

    Parameters:
    - `request`: HTTP request object to check existing cookies
    - `user`: UserLogin object containing username and password
    - `response`: HTTP response object for setting authentication cookies
    - `db`: Database session dependency for user authentication
    - `api_key`: API key header (X-API-Key) for service authentication

    Returns:
    - A dictionary containing:
        - Login success message
        - User subject (username)
        - Detailed user information from employee records

    Authentication Process:
    1. Validate Portal service API key
    2. Authenticate user credentials
    3. Fetch employee details from client API
    4. Verify user has Registrar role
    5. Clear existing authentication cookies
    6. Generate new access and refresh tokens
    7. Set secure HTTP-only cookies

    Raises:
    - `HTTPException(403)`: If the provided API key is invalid or expired
    - `HTTPException(405)`: If the user is not a Registrar

    Allowed Users:
    - Only users with Registrar role

    Security Measures:
    - API key validation
    - Role-based access control
    - Secure token generation
    - HTTP-only, secure cookies with SameSite=None
    - Existing session cookie management
    """
    if not validate_api_key(api_key=api_key, expected_service='portal', db=db):
        raise HTTPException(
            status_code=403, 
            detail="Invalid or expired API Key for Portal Service"
        )
    
    db_user = authenticate_user(db, user.username, user.password)
    employee_details = await requests.fetch_public_employee_data(f"{CLIENT_API_URL}?", db_user.identifier)
    
    if "Registrar" not in employee_details.get("role", ""):
        raise HTTPException(status_code=405, detail="Only registrar can log in")
    
    
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    if access_token:
        response.delete_cookie("access_token")
    if refresh_token:
        response.delete_cookie("refresh_token")
    
    # print(f"role: {employee_details["role"]}")
    access_token = create_access_token(data={
        "sub": db_user.username,
        "user_details": employee_details
        })
    refresh_token = create_refresh_token(data={"sub": db_user.username})
    
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True,  
        secure=True,    
        samesite="None"
    )
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token, 
        httponly=True,
        secure=True,
        samesite="None"
    )

    return {"message": "Login successful",
            "sub": db_user.username,
            "user_details": employee_details
            }




@router.post("/mod-login")
async def mod_login(user: UserLogin, response: Response, db: Session = Depends(get_db), api_key: str = Header(alias="X-API-Key")):
    """
    Authenticate and log in moderator for service access.

    This endpoint handles login specifically for moderator:
    - Requires a valid Mod service API key
    - Authenticates user credentials
    - Validates moderator-specific login requirements
    - Generates access and refresh tokens

    Parameters:
    - `user`: UserLogin object containing username and password.
    - `response`: HTTP response object for setting authentication cookies.
    - `db`: Database session dependency for user authentication.
    - `api_key`: API key header (X-API-Key) for service authentication.

    Returns:
    - A dictionary containing:
        - Login success message
        - User subject (username)
        - Moderator status flag

    Authentication Process:
    1. Validate Mod service API key
    2. Authenticate user credentials
    3. Verify user is a moderator
    4. Generate access and refresh tokens
    5. Set secure HTTP-only cookies

    Raises:
    - `HTTPException(403)`: If the provided API key is invalid or expired
    - `HTTPException(405)`: If the login attempt is not by a moderator user

    Allowed Users:
    - Only moderators

    Security Measures:
    - API key validation
    - Strict moderator-only access
    - Secure token generation
    - HTTP-only, secure cookies with SameSite=None with allowed CORS middleware
    """
    if not validate_api_key(api_key=api_key, expected_service='mod', db=db):
        raise HTTPException(
            status_code=403, 
            detail="Invalid or expired API Key for Mod Service"
        )

    db_user = authenticate_user(db, user.username, user.password)
    
    if not user.username == "mod":
        raise HTTPException(status_code=405, detail="only moderators can log in here")

    # print(f"role: {employee_details["role"]}")
    access_token = create_access_token(data={
        "sub": db_user.username,
        "mod": True,
        })
    refresh_token = create_refresh_token(data={"sub": db_user.username})
    
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True,  
        secure=True,    
        samesite="None"
    )
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token, 
        httponly=True,
        secure=True,
        samesite="None"
    )

    return {"message": "Login successful",
            "sub": db_user.username,
            "mod": True,            
            }


@router.post("/mis-login")
async def mis_login(user: UserLogin, response: Response, db: Session = Depends(get_db), api_key: str = Header(alias="X-API-Key")):
    """
    Authenticate and log in users for MIS-related services.

    This endpoint handles login for users with specific administrative roles:
    - Requires a valid MIS service API key
    - Authenticates user credentials
    - Validates user role (Registrar, MIS, or Accounting)
    - Generates access and refresh tokens

    Parameters:
    - `user`: UserLogin object containing username and password.
    - `response`: HTTP response object for setting authentication cookies.
    - `db`: Database session dependency for user authentication.
    - `api_key`: API key header (X-API-Key) for service authentication.

    Returns:
    - A dictionary containing:
        - Login success message
        - User subject (username)
        - User details from the MIS system

    Authentication Process:
    1. Validate MIS service API key
    2. Authenticate user credentials
    3. Fetch and verify employee details
    4. Check user role eligibility
    5. Generate access and refresh tokens
    6. Set secure HTTP-only cookies

    Raises:
    - `HTTPException(403)`: If the provided API key is invalid or expired
    - `HTTPException(405)`: If the user's role is not authorized 
      (not Registrar, MIS, or Accounting)

    Allowed Roles:
    - Registrar
    - MIS
    - Accounting

    Security Measures:
    - API key validation
    - Role-based access control
    - Secure token generation
    - HTTP-only, secure cookies
    """
    if not validate_api_key(api_key=api_key, expected_service='mis', db=db):
        raise HTTPException(
            status_code=403, 
            detail="Invalid or expired API Key for MIS Service"
        )
    
    db_user = authenticate_user(db, user.username, user.password)
    employee_details = await requests.fetch_public_employee_data(f"{CLIENT_API_URL}?", db_user.identifier)
    if not any(role in employee_details.get("role", "") for role in ["Registrar","MIS",'Accounting']):
        raise HTTPException(status_code=405, detail="Role must include either 'Registrar', 'MIS', 'Accounting")

    # print(f"is it a professor/instructor? {any(role in employee_details.get("role", "") for role in ["Instructor", "Professor"])}")
    # if "moderator" in employee_details.get("role", ""):
    #     raise HTTPException(status_code=405, detail="you cannot log in the moderator here")

    # print(f"role: {employee_details["role"]}")
    access_token = create_access_token(data={
        "sub": db_user.username,
        "user_details": employee_details
        })
    refresh_token = create_refresh_token(data={"sub": db_user.username})
    
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True,  
        secure=True,    
        samesite="None"
    )
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token, 
        httponly=True,
        secure=True,
        samesite="None"
    )

    return {"message": "Login successful",
            "sub": db_user.username,
            "user_details": employee_details
            }



@router.get("/verify-token")
async def verify_token(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Verify and refresh authentication tokens.

    This endpoint performs comprehensive token validation and handles token refresh:
    - Checks the presence and validity of access and refresh tokens
    - Validates token details against stored information
    - Handles token expiration and regeneration
    - Verifies user details for non-moderator users

    Parameters:
    - `request`: The incoming HTTP request containing authentication cookies.
    - `response`: The HTTP response object for setting new cookies.
    - `db`: Database session dependency for token management.

    Returns:
    - A dictionary containing:
        - Validation message
        - User subject (sub)
        - User details or moderator flag

    Token Validation Process:
    1. Extract access and refresh tokens from cookies
    2. Decode and verify access token
    3. Check for blocked token identifiers
    4. For non-moderator users:
        - Fetch and validate employee details
        - Regenerate access token if expired
    5. For moderator users:
        - Validate and regenerate access token as needed

    Raises:
    - `HTTPException(400)`: If tokens are not provided
    - `HTTPException(401)`: 
        - If tokens are invalid
        - If refresh token has expired
        - If user details mismatch
        - If tokens are blocked

    Security Measures:
    - Validates token integrity
    - Checks against blocked tokens
    - Verifies user details
    - Regenerates tokens securely
    - Handles moderator and non-moderator use cases
    """
    try:
        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")
        
        decoded_refresh_token = decode_tokens(refresh_token)

        if not access_token or not refresh_token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tokens not provided in the request")
        
        decoded_access_token_details = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        try:
            decoded_access_token = decode_tokens(access_token)
            db_access_jti = get_hashed_jti(db, decoded_access_token["jti"])
            if db_access_jti:
                # print(f"dbjti: {db_access_jti}")
                raise BlockedAccessTokenException()
            
            employee_details = None
            if not decoded_access_token.get("mod"):
                employee_details = await requests.fetch_public_employee_data(CLIENT_API_URL, decoded_access_token["user_details"].get("employee_id"))

                # print(f"decoded access token: {decoded_access_token["user_details"]}")
                # print(f"employee details: {employee_details}")
                if decoded_access_token["user_details"] != employee_details:
                    create_blocked_jti(db, decoded_access_token["jti"])
                    raise DataMismatchException()
            
                return {"message": "Access token is valid",                    
                        "sub": decoded_access_token["sub"],
                        "user_details": decoded_access_token["user_details"]
                        }
            
            return {"message": "Access token is valid",                    
                "sub": decoded_access_token["sub"],
                "mod": True
                }

        
        except (jwt.ExpiredSignatureError, DataMismatchException):
            
            db_refresh_jti = get_hashed_jti(db, decoded_refresh_token["jti"])
            if db_refresh_jti:
                # print(f"dbjti: {db_refresh_jti}")
                raise BlockedRefreshTokenException()

            if not decoded_access_token_details.get("mod", False):
                employee_details = await requests.fetch_public_employee_data(CLIENT_API_URL, decoded_access_token_details["user_details"].get("employee_id"))
                
                new_access_token = create_access_token(data={
                    "sub": decoded_refresh_token["sub"],
                    "user_details": employee_details
                })
            else:
                new_access_token = create_access_token(data={
                    "sub": decoded_refresh_token["sub"],
                    "mod": True
                })
            
            response.set_cookie(
                key="access_token",
                value=new_access_token,
                httponly=True,
                secure=True,
                samesite="None"
            )
            if not decoded_access_token_details.get("mod", False):
                return {"message": "Access token has expired, new access token has been generated",
                            "sub": decoded_access_token_details["sub"],
                            "user_details": employee_details
                        }
            else:
                return {"message": "Access token has expired, new access token has been generated",
                            "sub": decoded_access_token_details["sub"],
                            "mod": True
                        }

    except jwt.ExpiredSignatureError as e:
        print(f"exception error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired, please log in again"
        )
    
    except Exception as e:
        print(f"exception error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token"
        )
    
    
@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Logout a user by invalidating their access and refresh tokens.

    This endpoint handles the logout process by:
    - Validating the presence of access and refresh tokens
    - Decoding and checking the tokens
    - Blocking the token identifiers to prevent further use
    - Deleting authentication cookies from the client

    Parameters:
    - `request`: The incoming HTTP request containing authentication cookies.
    - `response`: The HTTP response object for cookie manipulation.
    - `db`: Database session dependency for token management.

    Returns:
    - A dictionary with a success logout message.

    Raises:
    - `HTTPException(400)`:
        - If the request object is invalid
        - If access or refresh tokens are missing
        - If tokens lack a valid token identifier (jti)
    - `HTTPException(401)`: If tokens are invalid or expired

    Process:
    1. Validates the request and token existence
    2. Decodes both access and refresh tokens
    3. Extracts and blocks token identifiers (jti)
    4. Deletes authentication cookies
    5. Prevents further use of the logged-out tokens

    Security Measures:
    - Blocks token identifiers to prevent token reuse
    - Removes client-side authentication cookies
    """
    if not isinstance(request, Request):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Invalid request object"
        )

    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    if not access_token or not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Tokens are required to log out"
        )
    
    try:
        decoded_access_token = decode_tokens(access_token)
        decoded_refresh_token = decode_tokens(refresh_token)

        access_jti = decoded_access_token.get("jti")
        refresh_jti = decoded_refresh_token.get("jti")

        if not access_jti or not refresh_jti:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid tokens provided"
            )

        create_blocked_jti(db, access_jti)
        create_blocked_jti(db, refresh_jti)

        # Delete the cookies
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

        return {"message": "Logged out successfully"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired tokens provided"
        )    


@router.post("/create-api-key")
def create_service_api_key(request: Request, service: str, db: Session = Depends(get_db)):
    """
    Create a new API key for a specific service by a moderator.

    This endpoint allows moderators to generate API keys for predefined services. 
    It requires both access and refresh tokens for authentication and verifies 
    the requester has moderator privileges.

    Parameters:
    - `request`: The incoming HTTP request containing authentication cookies.
    - `service`: The name of the service for which the API key is being created.
    - `db`: Database session dependency for API key generation.

    Returns:
    - A dictionary containing the newly created API key and the associated service.

    Raises:
    - `HTTPException(400)`: 
        - If access or refresh tokens are missing from the request.
        - If the specified service is not in the list of valid services.
    - `HTTPException(405)`: If the requester is not a moderator.

    Supported Services:
    - 'grading'
    - 'mis'
    - 'scheduling'
    - 'portal'
    - 'mod'

    Requirements:
    - Authenticated request with moderator access.
    - Service must be one of the predefined valid services.
    """
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    if not access_token or not refresh_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tokens not provided in the request")

    decoded_access_token = decode_tokens(access_token)
    # print(f"is it a moderator?: {decoded_access_token["mod"]}")
    if not decoded_access_token["mod"]:
        raise HTTPException(status_code=405, detail="only moderators can create api tokens")

    valid_services = ['grading', 'mis','scheduling','portal', 'mod']
    if service not in valid_services:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid service. Must be one of {valid_services}"
        )
    

    api_key = create_api_key(db, service)
    return {"api_key": api_key, "service": service}

@router.post("/change-password")
def change_user_password(user: UserLogin, db: Session = Depends(get_db), api_key: str = Header(alias="X-API-Key")):
    """
    Change a user's password through a moderator-authorized API endpoint.

    This endpoint allows moderators to change a user's password using a validated API key.
    It requires a specific mod service API key to authenticate the request.

    Parameters:
    - `user`: UserLogin object containing the username and new password.
    - `db`: Database session dependency for performing password change operations.
    - `api_key`: API key header (X-API-Key) for service authentication.

    Returns:
    - A dictionary with a success message upon password change.

    Raises:
    - `HTTPException(403)`: If the provided API key is invalid, expired, or not for the mod service.

    Requirements:
    - Requires a valid moderator service API key.
    - The user must provide a username and new password.
    """
    if not validate_api_key(api_key=api_key, expected_service='mod', db=db):
        raise HTTPException(
            status_code=403, 
            detail="Invalid or expired API Key for mod Service"
        )
    
    change_password(db=db, username=user.username, new_password=user.password)

    return {"message": "Password changed successfully!"}


@router.get("/users", response_model=List[UserResponse])
def view_all_users( request: Request,db: Session = Depends(get_db)):
    """
    Retrieve all users with moderator access.

    This endpoint allows only moderators to view a list of all users in the system.
    It requires both access and refresh tokens to be present in the request cookies.

    Parameters:
    - `request`: The incoming HTTP request containing authentication cookies.
    - `db`: Database session dependency for querying user information.

    Returns:
    - A list of user responses containing user details.

    Raises:
    - `HTTPException(400)`: If access or refresh tokens are missing from the request.
    - `HTTPException(405)`: If the requester is not a moderator.
    """
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    if not access_token or not refresh_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tokens not provided in the request")

    decoded_access_token = decode_tokens(access_token)
    # print(f"is it a moderator?: {decoded_access_token["mod"]}")
    if not decoded_access_token.get("mod"):
        raise HTTPException(status_code=405, detail="only moderators can view all the users")

    users = get_all_users(db)
    return users

@router.get("/proxy")
async def proxy_get_request(
    request: Request, 
    url: str = Query(..., description="Full URL to proxy"),
    api_key: str = Header(alias="X-API-Key"), 
    db: Session = Depends(get_db)
):
    """
    Proxy a GET request to an external API.

    This endpoint allows you to make a GET request to an external API while verifying the API key and allowing access only to a set of approved domains.
    - `requirements`: Only `moderators` can/should access this api endpoint.

    Parameters:
    - `request`: The incoming HTTP request.
    - `url`: The full URL of the external API endpoint to proxy.
    - `api_key`: The API key to validate the request.
    - `db`: The database session for validating the API key.

    Returns:
    - The JSON response from the external API.

    Raises:
    - `HTTPException(403)`: If the API key is invalid or expired, or the target domain is not allowed.
    - `HTTPException(503)`: If there is a failure to connect to the external API.
    """
    if not validate_api_key(api_key=api_key, expected_service='mod', db=db):
        raise HTTPException(
            status_code=403, 
            detail="Invalid or expired API Key"
        )
    
    allowed_domains = [
        "node-mysql-signup-verification-api.onrender.com"
    ]
    
    parsed_url = urlparse(url)
    if parsed_url.netloc not in allowed_domains:
        raise HTTPException(
            status_code=403, 
            detail="Access to this domain is not allowed"
        )
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=request.query_params)
            
            response.raise_for_status()
            return response.json()
    
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code, 
            detail=f"External API error: {str(e)}"
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
            detail=f"Failed to connect to external API: {str(e)}"
        )