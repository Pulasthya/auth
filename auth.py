from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
import models, database, utils
import uuid

# Secret Key (Change for production)
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_access_token(email: str):
    return create_token({"sub": email}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

def create_refresh_token(db: Session, user_id: str, device_info: str) -> str:
    # Check if a refresh token already exists for the user
    existing_session = db.query(models.UserSession).filter(
                models.UserSession.user_id == user_id,
                models.UserSession.device_info == device_info
            ).first()

    if existing_session:
        # If token is still valid, return it
        if existing_session.expires_at > datetime.utcnow():
            return existing_session.refresh_token
        
        # If token has expired, delete it
        db.delete(existing_session)
        # db.commit()

    refresh_token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    session = models.UserSession(
        user_id=user_id,
        refresh_token=refresh_token,
        device_info=device_info,
        expires_at=expires_at
    )
    db.add(session)
    # db.commit()
    
    return refresh_token

def verify_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        expiration_time = payload.get("exp")
        if expiration_time is None or expiration_time > datetime.utcnow():
            raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Your token has expired. Obtain a new one by logging in again or refreshing your session.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        return email
    except JWTError:
        raise credentials_exception

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    email = verify_token(token, credentials_exception)
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user
