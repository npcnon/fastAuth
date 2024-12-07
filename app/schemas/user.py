from pydantic import BaseModel, EmailStr, field_validator
import re
from typing import List
from ..models import UserRole

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: List[str] 

    @field_validator('role')
    @classmethod
    def validate_roles(cls, v):
        valid_roles = {role.value for role in UserRole}
        for role in v:
            if role not in valid_roles:
                raise ValueError(f'Invalid role: {role}. Valid roles are: {valid_roles}')
        return v

    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters long')
        
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username can only contain letters, numbers, and underscores')
        
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        
        return v
    

class UserLogin(BaseModel):
    username: str
    password: str

class UserRefresh(BaseModel):
    refresh_token: str