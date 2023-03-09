import os
from typing import List
from fastapi import APIRouter, Depends, UploadFile, status, HTTPException
from urllib import parse
from minio import InvalidResponseError

from src.config.settings import Allowed_types, MinioBaseUrl
from src.config.storage import minio_client, bucket
from src.models.user import User

from ..models.items import Item, UpdateItem
from .. import oauth2

router = APIRouter()

@router.get('/', response_model=List[Item])
async def get_all():
    print(oauth2.require_user)
    return []

@router.post('/', response_model=Item)
async def create_item(user_id: str = Depends(oauth2.require_creator),  ):
    user = await User.get(str(user_id))