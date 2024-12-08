from datetime import datetime, timedelta
import secrets
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.models import APIKey
import pytz  # Recommended for timezone handling

def generate_unique_api_key(db: Session):
    while True:
        try:
            api_key = secrets.token_urlsafe(32)
            
            existing_key = db.query(APIKey).filter(APIKey.key == api_key).first()
            
            if not existing_key:
                return api_key
        
        except IntegrityError:
            continue

def validate_api_key(db: Session, api_key: str, expected_service: str):
    # Use Philippines timezone
    philippines_tz = pytz.timezone('Asia/Manila')
    current_time = datetime.now(philippines_tz)
    
    db_key = db.query(APIKey).filter(
        APIKey.key == api_key, 
        APIKey.service == expected_service,
        APIKey.is_active == True,
        APIKey.expires_at > current_time
    ).first()
    
    return db_key is not None

def create_api_key(db: Session, service: str, expires_days: int = 30):
    key = generate_unique_api_key(db)
    
    philippines_tz = pytz.timezone('Asia/Manila')
    current_time = datetime.now(philippines_tz)
    expires_at = current_time + timedelta(days=expires_days)
    
    api_key = APIKey(
        key=key,
        service=service,
        created_at=current_time,
        expires_at=expires_at,
        is_active=True
    )
    
    db.add(api_key)
    db.commit()
    db.refresh(api_key)
    
    return key