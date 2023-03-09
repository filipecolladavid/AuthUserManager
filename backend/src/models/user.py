from datetime import datetime
from pydantic import BaseModel, EmailStr
from typing import Optional
from beanie import Document

# Previleges:
# - admin: Accepts users, verifies them and labels them, can create content -> verified: true
# - creator: can create content -> verified: true
# - visitor: can browse -> verified: true
# - pending: To be accepted by admin -> verified: false


class Privileges:
    ADMIN = 3
    CREATOR = 2
    VISITOR = 1
    PENDING = 0


class Register(BaseModel):
    username: str
    email: EmailStr
    password: str


class Login(BaseModel):
    username: str
    password: str

class UserPrivileges(BaseModel):
    username: str
    privileges: str

class UserResponse(BaseModel):
    username: str
    email: EmailStr
    verified: bool
    privileges: int
    created_at: datetime
    pic_url: Optional[str] = None
        

# This is the model that will be saved to the database
class User(Document):
    username: str
    email: EmailStr
    password: str
    verified: bool
    privileges: int
    created_at: datetime
    pic_url: Optional[str] = None
