from datetime import datetime
import os
from typing import List
from fastapi import APIRouter, Depends, UploadFile, status, HTTPException
from urllib import parse
from minio import InvalidResponseError

from src.config.settings import Allowed_types, MinioBaseUrl
from src.config.storage import minio_client, bucket
from src.models.user import Privileges, User

from ..models.items import Item, UpdateItem, Visibility
from .. import oauth2

router = APIRouter()


# Returns posts filtered by who's making the request
@router.get('/', response_model=List[Item])
async def get_all(user_id: str = Depends(oauth2.require_id)):
    if not user_id:
        all_items_cursor = Item.find(Item.visibility <= Visibility.ALL)

    else:
        user = await User.get(user_id)
        if user.privileges <= Privileges.CREATOR:
            all_items_cursor = Item.find(Item.visibility <= Visibility.USERS)
        if user.privileges >= Privileges.ADMIN:
            all_items_cursor = Item.find(Item.visibility <= Visibility.ADMIN)

    return await all_items_cursor.to_list(length=None)


# Create an Item - requires creator privilege
@router.post('/', response_model=Item)
async def create_item(
        img: UploadFile,
        title: str,
        desc: str,
        visibility: str = "all",
        user_id: str = Depends(oauth2.require_creator)):
    user = await User.get(str(user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    v = 0
    if visibility == "all":
        v = Visibility.ALL
    elif visibility == "users":
        v = Visibility.USERS
    elif visibility == "admin":
        v = Visibility.ADMIN
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Visibility not valid"
        )

    if img.content_type not in Allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid type of file"
        )

    item = Item(
        title=title,
        desc=desc,
        visibility=v,
        author=user.username,
        pic_url=None,
        created_at=datetime.utcnow()
    )

    await item.create()

    file_size = os.fstat(img.file.fileno()).st_size
    file_name = str(user.id)+"_"+str(item.id)+"." + \
        img.content_type.split("/")[1]

    try:
        minio_client.put_object(
            bucket,
            file_name,
            img.file,
            file_size,
            img.content_type
        )
        publicUrl = MinioBaseUrl+bucket+"/"+parse.quote(file_name)
    except InvalidResponseError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err.message
        )

    item.pic_url = publicUrl
    await item.save()
    return item


# # Update a post - require_user vs require_creator it's privileges might have changed
# @router.put('/{item_id}', response_model=Item)
# async def update_item(item_id=str, user_id: str = Depends(oauth2.require_user)):
#     user =

# Delete a post - require_user vs require_creator it's privileges might have changed
@router.delete('/{item_id}', response_model=Item)
async def delete_item(item_id=str, user_id: str = Depends(oauth2.require_user)):
    user = User.get(user_id)

    if user.username != item.author or user.privilege < Privileges.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Need admin privilege to delete another users post"
        )

    item = Item.get(item_id)

    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post does not exist anymore"
        )

    await item.delete()

    return item
