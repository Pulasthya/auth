from sqlalchemy import Column, String, Integer, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime, timedelta

class User(Base):
    __tablename__ = "users"
    
    email = Column(String, primary_key=True, index=True)
    hashed_password = Column(String)

    # Relationship to user details
    details = relationship("UserDetails", back_populates="user", uselist=False)

class UserDetails(Base):
    __tablename__ = "user_details"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, ForeignKey("users.email"))
    full_name = Column(String)
    age = Column(Integer)
    role = Column(String)

    user = relationship("User", back_populates="details")

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.email"))
    refresh_token = Column(String, unique=True)
    device_info = Column(String)
    last_used = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)

    user = relationship("User", back_populates="sessions")