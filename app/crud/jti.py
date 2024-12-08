import hashlib
from app.models.blacklisted_tokens import BlackListedTokens
from sqlalchemy.orm import Session


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

