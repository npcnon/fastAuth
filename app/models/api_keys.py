from datetime import datetime
from app.database import Base
from sqlalchemy import Boolean, Column, DateTime, Integer, String

class APIKey(Base):
    __tablename__ = 'api_keys'
    
    id = Column(Integer, primary_key=True)
    key = Column(String(225), unique=True)
    service = Column(String(40)) 
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)