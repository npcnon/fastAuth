from app.database import Base
from sqlalchemy import Column, Integer, String

class BlackListedTokens(Base):
    id = Column(Integer, primary_key=True, index=True)
    hashed_jti = Column(String(225), unique=True, index=True, nullable=False)
