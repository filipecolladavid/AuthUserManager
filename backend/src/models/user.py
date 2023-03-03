from datetime import datetime
from pydantic import BaseModel
from typing import Optional
from beanie import Document

# Previleges:
# - admin: Accepts users, verifies them and labels them, can create content -> verified: true
# - creator: can create content -> verified: true
# - visitor: can browse -> verified: true
# - pending: To be accepted by admin -> verified: false


class Previleges:
    ADMIN = "admin"
    CREATOR = "creator"
    VISITOR = "visitor"
    PENDING = "pending"


class Register(BaseModel):
    username: str
    email: str
    password: str


class Login(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    username: str
    email: str
    pic_url: str

# This is the model that will be saved to the database
class User(Document):
    username: str
    email: str
    password: str
    verified: bool
    privileges: str
    created_at: Optional[datetime] = None
    pic_url: Optional[str] = None
