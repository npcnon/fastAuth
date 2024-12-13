from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.utils.security import setup_rate_limiting
from . import models, schemas
from .database import engine, get_db
from .routes.auth import router as auth_router

# Initialize FastAPI app
app = FastAPI(
    title="AUTHENTICATION SYSTEM",
    description="A FastAPI Authentication project\n\n[Link to Google Docs for comprehensive guide](https://docs.google.com/document/d/1mUjlJzCd1Aa-_ZclxMSAZs9OOFstESWh8aSwRLmEAIs/edit?tab=t.6bncxdjw1hly)",
    version="1.2.0"
)
setup_rate_limiting(app)

origins = [
    "http://localhost:3000",  
    "https://auth-front-iota.vercel.app",  
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"], 
)

# Include the authentication routes
app.include_router(auth_router)

@app.get("/")
def read_root():
    return {"message": "Welcome to FastAPI"}



# Create tables (after the app is initialized)
models.User.metadata.create_all(bind=engine)
