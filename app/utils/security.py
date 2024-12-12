from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt
import pytz
from dotenv import load_dotenv
import os
import uuid
from fastapi import FastAPI, HTTPException, Request, status
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_WEEKS = 1
load_dotenv() 
SECRET_KEY = os.getenv("SECRET_KEY")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(pytz.UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})

    jti = str(uuid.uuid4()) + str(datetime.now(pytz.UTC))
    to_encode.update({"jti": jti})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(pytz.UTC) + timedelta(weeks=REFRESH_TOKEN_EXPIRE_WEEKS)
    to_encode.update({"exp": expire})

    jti = str(uuid.uuid4()) + str(datetime.now(pytz.UTC))
    to_encode.update({"jti": jti})


    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_tokens(token: str):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if datetime.fromtimestamp(decoded_token["exp"], tz=pytz.UTC) < datetime.now(pytz.UTC):
            print(f"token details: {decoded_token}") 
            raise jwt.ExpiredSignatureError
        
        return decoded_token

    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError("The token has expired")
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token"
        )


# Create a rate limiter with more flexible configuration
def create_rate_limiter():
    # Configurable rate limits
    return Limiter(
        key_func=get_remote_address,
        default_limits=["100/minute"],  # Default limit for all routes
        # You can add more specific limits as needed
    )


def setup_rate_limiting(app: FastAPI):
    limiter = create_rate_limiter()
    
    app.state.limiter = limiter
    
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    
    app.add_middleware(SlowAPIMiddleware)
    
    @limiter.limit("5/minute")
    async def login_rate_limit(request: Request):
        return request
    
    @limiter.limit("20/minute")
    async def token_verify_rate_limit(request: Request):
        return request
    
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        path = request.url.path
        
        if path.startswith("/auth/login"):
            try:
                await login_rate_limit(request)
            except RateLimitExceeded:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS, 
                    detail="Too many login attempts. Please try again later."
                )
        
        elif path.startswith("/auth/verify-token"):
            try:
                await token_verify_rate_limit(request)
            except RateLimitExceeded:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS, 
                    detail="Too many token verification attempts. Please try again later."
                )
        
   
        response = await call_next(request)
        return response

#custom route limiter
def apply_route_rate_limit(route_func):
    """
    Decorator to apply rate limiting to a specific route
    Usage: @app.post("/some-route")
           @apply_route_rate_limit
           async def some_route():
               ...
    """
    def wrapper(request: Request):
        limiter = Limiter(key_func=get_remote_address)
        
        # Default route-specific rate limit
        @limiter.limit("10/minute")
        async def limited_route(request: Request):
            return request
        
        try:
            limited_route(request)
        except RateLimitExceeded:
            raise HTTPException(
                status_code=429, 
                detail="Too many requests. Please try again later."
            )
        
        return route_func(request)
    
    return wrapper


