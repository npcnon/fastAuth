
from sqlalchemy import Column, Integer, String
from sqlalchemy.dialects.mysql import JSON as MySQLJSON
import enum
from app.database import Base

class UserRole(enum.Enum):
    MODERATOR = "moderator" #sa atoa authsystem rani magamit

    ADMIN = "admin"
    SUPERADMIN = "superadmin"
    MIS = "mis"
    DATACENTER = "datacenter"
    PROFESSOR = "professor"
    INSTRUCTOR = "instructor"
    DEAN = "dean"
    ACCOUNTING = "accounting"
    REGISTRAR = "registrar"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(225), unique=True, index=True, nullable=False)
    email = Column(String(225), unique=True, index=True, nullable=False)
    hashed_password = Column(String(225), nullable=False)
    role = Column(MySQLJSON, nullable=False)
    identifier = identifier = Column(String(50), unique=True, index=True, nullable=False)

    @property
    def roles(self):
        """
        Convert stored JSON roles to UserRole enum instances
        """
        return [UserRole(role) for role in self.role]

    @roles.setter
    def roles(self, roles):
        """
        Convert roles to their string values before storing
        """
        self.role = [role.value if isinstance(role, UserRole) else role for role in roles]

    def has_role(self, role):
        """
        Check if user has a specific role
        """
        return role.value in self.role or role in self.role