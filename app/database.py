import os
from urllib.parse import quote_plus
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Encode username and password separately
encoded_username = quote_plus(os.getenv('DB_USERNAME'))
encoded_password = quote_plus(os.getenv('DB_PASSWORD'))

# Construct DATABASE_URL with properly encoded components
DATABASE_URL = f'mysql+pymysql://{encoded_username}:{encoded_password}@{os.getenv("DB_HOST")}/{os.getenv("DB_NAME")}'

# Create SQLAlchemy engine
engine = create_engine(
    DATABASE_URL, 
    pool_pre_ping=True,  # Test connections before using them
    pool_recycle=3600,   # Refresh connections every hour
)

# Create SessionLocal class
SessionLocal = sessionmaker(
    autocommit=False, 
    autoflush=False, 
    bind=engine
)

# Base class for models
Base = declarative_base()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()