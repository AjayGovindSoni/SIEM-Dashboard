from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, DateTime, Boolean

from models import Base
from db import get_db


SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

security_bearer = HTTPBearer()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ================= MODELS =================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="analyst")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    key = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    user_id = Column(Integer)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime)
    expires_at = Column(DateTime)


# ================= SCHEMAS =================

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"


class UserLogin(BaseModel):
    username: str
    password: str


# ================= HELPERS =================

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires: Optional[timedelta] = None):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + (expires or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return None

    user.last_login = datetime.utcnow()
    db.commit()
    return user


# ================= DEPENDENCIES =================

def get_current_user_from_token(
    credentials: HTTPAuthorizationCredentials = Security(security_bearer),
    db: Session = Depends(get_db),
):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise Exception()
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Inactive user")

    return user


def get_current_user_from_api_key(
    api_key: str = Security(api_key_header),
    db: Session = Depends(get_db),
):
    if not api_key:
        return None

    key = db.query(APIKey).filter(APIKey.key == api_key).first()
    if not key or not key.is_active:
        return None

    if key.expires_at and key.expires_at < datetime.utcnow():
        return None

    key.last_used = datetime.utcnow()
    db.commit()

    if key.user_id:
        return db.query(User).filter(User.id == key.user_id).first()

    return None


def get_current_user(
    token_user: Optional[User] = Depends(get_current_user_from_token),
    api_user: Optional[User] = Depends(get_current_user_from_api_key),
):
    user = token_user or api_user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_role(role: str):
    def checker(user: User = Depends(get_current_user)):
        levels = {"viewer": 0, "analyst": 1, "admin": 2}
        if levels.get(user.role, 0) < levels.get(role, 0):
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return checker


def create_default_admin(db: Session):
    if not db.query(User).filter(User.role == "admin").first():
        admin = User(
            username="admin",
            email="admin@siem.local",
            hashed_password=get_password_hash("admin123"),
            role="admin",
        )
        db.add(admin)
        db.commit()

