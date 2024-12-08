from fastapi import APIRouter, Depends, HTTPException, Request, status, Response
import httpx
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import UserRole
from app.schemas.user import UserCreate, UserLogin
from app.exceptions import DataMismatchException, BlockedAccessTokenException, BlockedRefreshTokenException
from app.crud.user import get_user_by_email_or_username, create_user, authenticate_user, create_blocked_jti, get_hashed_jti
from app.utils.security import create_access_token, create_refresh_token, decode_tokens
import os
from dotenv import load_dotenv
from app.utils import requests
from jose import jwt
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
CLIENT_API_URL=os.getenv("CLIENT_API_URL")
ALGORITHM = "HS256"

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email_or_username(db, user.username, user.email)
    if db_user:
        print(f"dbuser: {db_user}")
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
async def login(user: UserLogin, response: Response, db: Session = Depends(get_db)):
    db_user = authenticate_user(db, user.username, user.password)
    employee_details = await requests.fetch_public_employee_data(f"{CLIENT_API_URL}?", db_user.identifier)
    
    print(f"is it a professor/instructor? {any(role in employee_details.get("role", "") for role in ["Instructor", "Professor"])}")
    if not any(role in employee_details.get("role", "") for role in ["Instructor", "Professor"]):
        raise HTTPException(status_code=405, detail="Role must include either 'Instructor' or 'Professor'")

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
        secure=False,    
        samesite="lax"
    )
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token, 
        httponly=True,
        secure=False,
        samesite="lax"
    )

    return {"message": "Login successful"}

@router.post("/mis-login")
async def login(user: UserLogin, response: Response, db: Session = Depends(get_db)):
    db_user = authenticate_user(db, user.username, user.password)
    employee_details = await requests.fetch_public_employee_data(f"{CLIENT_API_URL}?", db_user.identifier)
    
    print(f"is it a professor/instructor? {any(role in employee_details.get("role", "") for role in ["Instructor", "Professor"])}")
    if "moderator" in employee_details.get("role", ""):
        raise HTTPException(status_code=405, detail="you cannot log in the moderator here")

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
        secure=False,    
        samesite="lax"
    )
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token, 
        httponly=True,
        secure=False,
        samesite="lax"
    )

    return {"message": "Login successful"}



@router.get("/verify-token")
async def verify_token(request: Request, response: Response, db: Session = Depends(get_db)):
    try:
        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")
        
        if not access_token or not refresh_token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Tokens not provided in the request")
        decoded_access_token = decode_tokens(access_token)
        db_access_jti = get_hashed_jti(db, decoded_access_token["jti"])
        if db_access_jti:
            print(f"dbjti: {db_access_jti}")
            raise BlockedAccessTokenException()

        employee_details = await requests.fetch_public_employee_data(CLIENT_API_URL, decoded_access_token["user_details"].get("employee_id"))

        # print(f"decoded access token: {decoded_access_token["user_details"]}")
        # print(f"employee details: {employee_details}")
        if decoded_access_token["user_details"] != employee_details:
            create_blocked_jti(db, decoded_access_token["jti"])
            raise DataMismatchException()
        return {"message": "Access token is valid"}

    except (jwt.ExpiredSignatureError, DataMismatchException) as e:
        try:
            decoded_refresh_token = decode_tokens(refresh_token)
            db_refresh_jti = get_hashed_jti(decoded_refresh_token["jti"])
            if db_refresh_jti:
                print(f"dbjti: {db_refresh_jti}")
                raise BlockedAccessTokenException()


            new_access_token = create_access_token(data={
                "sub": decoded_access_token["sub"],
                "user_details": employee_details
                })
            response.set_cookie(
                key="access_token",
                value=new_access_token,
                httponly=True,
                secure=False,
                samesite="lax"
            )

            return {"message": "Access token has expired, new access token has been generated"}

        except jwt.ExpiredSignatureError:
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
    
#TODO: add api keys and segregate user log in route for different roles
#TODO: last add a basic front end for managing users
