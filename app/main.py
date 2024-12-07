from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from . import models, schemas
from .database import engine, get_db
from .routes.auth import router as auth_router

# Initialize FastAPI app
app = FastAPI(
    title="My FastAPI Project",
    description="A sample FastAPI project with MariaDB",
    version="0.1.0"
)

# List of allowed origins (adjust to match your frontend's origin)
origins = [
    "http://localhost:3000",  # Next.js dev server
    "https://yourfrontend.com",  # Your frontend production URL
]

# Adding CORS middleware to the app
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allows specific origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers (including Authorization)
)

# Include the authentication routes
app.include_router(auth_router)

@app.get("/")
def read_root():
    return {"message": "Welcome to FastAPI"}

@app.get("/users")
def list_users(db: Session = Depends(get_db)):
    users = db.query(models.User).all()
    return users

# Create tables (after the app is initialized)
models.User.metadata.create_all(bind=engine)
