from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.user import UserCreate, UserLogin
from app.crud.user import get_user_by_email_or_username, create_user, authenticate_user
from app.utils.security import create_access_token
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user already exists
    db_user = get_user_by_email_or_username(db, user.username, user.email)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    # Create new user
    return create_user(db, user.username, user.email, user.password, user.role)

@router.post("/login")
def login(user: UserLogin, response: Response, db: Session = Depends(get_db)):
    # Authenticate user
    db_user = authenticate_user(db, user.username, user.password)

    # Create tokens
    access_token = create_access_token(data={"sub": db_user.username})
    refresh_token = create_access_token(data={"sub": db_user.username})

    # Set cookies
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

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"message": "Logged out successfully"}
