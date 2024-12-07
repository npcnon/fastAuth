import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from alembic.config import Config

# Load environment variables
load_dotenv()

# Get DATABASE_URL from environment variables
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root@localhost/fastauth")

# Create Alembic configuration
alembic_config = Config("alembic.ini")
alembic_config.set_main_option('sqlalchemy.url', DATABASE_URL)

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