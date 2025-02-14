from sqlalchemy import Column, String, Integer, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

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
