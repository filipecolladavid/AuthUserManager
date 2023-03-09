from datetime import datetime
from pydantic import BaseModel
from typing import Optional
from beanie import Document


# Visibility:
# - all: anyone can see the item
# - users: only authenticated and verified users can see the item
# - admin: only admin and item author can see the item
class Visibility:
    ALL = 0
    USERS = 1
    ADMIN = 2


# For this template I'll be using images as the item
class UpdateItem(BaseModel):
    title: Optional[str]
    desc: Optional[str]

# This is the model that will be saved to the database
class Item(Document):
    title: str
    desc: str
    visibility: int
    author: str  # refers to author username (they're unique)
    pic_url: str
    created_at: Optional[datetime] = None
