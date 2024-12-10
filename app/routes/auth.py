from fastapi import APIRouter, Depends, HTTPException, Header, Request, status, Response
import httpx
from sqlalchemy.orm import Session
from app.crud.api_keys import create_api_key, validate_api_key
from app.database import get_db
from app.models.user import UserRole
from app.schemas.user import UserCreate, UserLogin
from app.crud.jti import create_blocked_jti, get_hashed_jti
from app.exceptions import DataMismatchException, BlockedAccessTokenException, BlockedRefreshTokenException
from app.crud.user import change_password, get_user_by_email_or_username, create_user, authenticate_user
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
async def register(request: Request,user: UserCreate, db: Session = Depends(get_db)):
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


@router.post("/scheduling-login")
async def scheduling_login(request: Request,user: UserLogin, response: Response, db: Session = Depends(get_db), api_key: str = Header(alias="X-API-Key")):
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

@router.post("/portal-login")
async def portal_login(request: Request,user: UserLogin, response: Response, db: Session = Depends(get_db), api_key: str = Header(alias="X-API-Key")):
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




@router.post("/mod-login")
async def mod_login(user: UserLogin, response: Response, db: Session = Depends(get_db), api_key: str = Header(alias="X-API-Key")):
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
async def mis_login(user: UserLogin, response: Response, db: Session = Depends(get_db), api_key: str = Header(alias="X-API-Key")):
    if not validate_api_key(api_key=api_key, expected_service='mis', db=db):
        raise HTTPException(
            status_code=403, 
            detail="Invalid or expired API Key for MIS Service"
        )
    
    db_user = authenticate_user(db, user.username, user.password)
    employee_details = await requests.fetch_public_employee_data(f"{CLIENT_API_URL}?", db_user.identifier)
    
    # print(f"is it a professor/instructor? {any(role in employee_details.get("role", "") for role in ["Instructor", "Professor"])}")
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
            # print(f"dbjti: {db_access_jti}")
            raise BlockedAccessTokenException()
        db_user = get_user_by_email_or_username(db, decoded_access_token.get("sub"), "examplemod321as3agdbc3@examplemod.com")
        employee_details = None
        if db_user == None:
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
            db_refresh_jti = get_hashed_jti(db, decoded_refresh_token["jti"])
            if db_refresh_jti:
                # print(f"dbjti: {db_refresh_jti}")
                raise BlockedRefreshTokenException()

            if db_user == None:
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

            new_access_token = create_access_token(data={
                "sub": decoded_access_token["sub"]
                })
            response.set_cookie(
                key="access_token",
                value=new_access_token,
                httponly=True,
                secure=False,
                samesite="lax"
            )
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired, please log in again"
            )

    except Exception as e:
        # print(f"exception error: {e}")
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


@router.post("/create-api-key")
def create_service_api_key(request: Request, service: str, db: Session = Depends(get_db)):
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
    
    if not validate_api_key(api_key=api_key, expected_service='mod', db=db):
        raise HTTPException(
            status_code=403, 
            detail="Invalid or expired API Key for mod Service"
        )
    
    change_password(db=db, username=user.username, new_password=user.password)

    return {"message": "Password changed successfully!"}

#TODO: last add a basic front end for managing users
