from pydantic import BaseModel
from typing import Optional

class UserCreate(BaseModel):
    email: str
    password: str
    full_name: str
    age: int
    role: str

class UserDetailsResponse(BaseModel):
    email: str
    full_name: str
    age: int
    role: str

    class Config:
        from_attributes = True

class TokenData(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"