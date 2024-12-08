from sqlalchemy.orm import Session
from app.models.user import User
from app.models.blacklisted_tokens import BlackListedTokens
from app.utils.security import get_password_hash, verify_password
from fastapi import HTTPException, status
import hashlib


def get_user_by_email_or_username(db: Session, username: str, email: str):
    return db.query(User).filter((User.username == username) | (User.email == email)).first()

def create_user(db: Session, username: str, email: str, password: str, role: str, identifier: str):
    hashed_password = get_password_hash(password)
    db_user = User(username=username, email=email, hashed_password=hashed_password, role=role, identifier=identifier)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username: str, password: str):
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user or not verify_password(password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect username or password"
        )
    return db_user

def create_blocked_jti(db: Session, jti: str):
    # Hash the jti using SHA-256
    hashed_jti = hashlib.sha256(jti.encode('utf-8')).hexdigest()

    db_blocked_jti = BlackListedTokens(hashed_jti=hashed_jti)
    db.add(db_blocked_jti)
    db.commit()
    db.refresh(db_blocked_jti)
    
    return db_blocked_jti

def get_hashed_jti(db: Session, jti: str):
    hashed_jti = hashlib.sha256(jti.encode('utf-8')).hexdigest()

    return db.query(BlackListedTokens).filter((BlackListedTokens.hashed_jti == hashed_jti)).first()

