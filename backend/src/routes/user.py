import os
from typing import List
from fastapi import APIRouter, Depends, UploadFile, status, HTTPException
from urllib import parse
from minio import InvalidResponseError

from src.config.settings import Allowed_types, MinioBaseUrl
from src.config.storage import minio_client, bucket_thumbnails

from ..models.user import User, UserResponse, Privileges, UserPrivileges
from .. import oauth2

router = APIRouter()


@router.get('/me', response_model=UserResponse)
async def get_me(user_id: str = Depends(oauth2.require_user)):

    user = await User.get(str(user_id))
    r_user = UserResponse(
        username=user.username,
        email=user.email,
        pic_url=str(user.pic_url)
    )
    return r_user


@router.get('/get/{username}', response_model=User)
async def get_user_info(username: str, user_id: str = Depends(oauth2.require_admin)):
    print(username)
    user = await User.find_one(User.username == username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='User does not exist',
        )

    return user


@router.get('/get', response_model=List[User])
async def get_all(user_id: str = Depends(oauth2.require_admin)):
    # Find all documents in the collection
    all_users_cursor = User.find({})
    all_users = await all_users_cursor.to_list(length=None)

    return all_users


@router.post('/verify/{username}', response_model=User)
async def verify_user(username: str, user_id: str = Depends(oauth2.require_admin)):
    user = await User.find_one(User.username == username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already verified"
        )

    user.verified = True

    await user.save()

    return user


@router.post('/previleges/', response_model=User)
async def change_user_previleges(data: UserPrivileges, user_id: str = Depends(oauth2.require_admin)):
    user = await User.find_one(User.username == data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='User does not exit',
        )

    if not user.verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not verified"
        )

    privileges = ""

    if data.privileges.lower() == Privileges.ADMIN:
        privileges = Privileges.ADMIN
    elif data.privileges.lower() == Privileges.CREATOR:
        privileges = Privileges.CREATOR
    elif data.privileges.lower() == Privileges.PENDING:
        privileges = Privileges.PENDING
    elif data.privileges.lower() == Privileges.VISITOR:
        privileges = Privileges.VISITOR
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid privilege",
        )

    user.privileges = privileges

    await user.save()

    return user


@router.post('/profile_pic/', response_model=UserResponse)
async def change_profile_picture(username: str, img: UploadFile, user_id: str = Depends(oauth2.require_user)):
    # To be changed
    user = await User.find_one(User.username == username)

    # Requesting the change
    req_user = await User.get(str(user_id))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if req_user.privileges != "admin" and str(user.id) != str(user_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Need admin privilege to change another's user profile picture",
        )

    if img.content_type not in Allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid type of file"
        )

    file_size = os.fstat(img.file.fileno()).st_size
    file_name = username+"_thumbnail."+img.content_type.split("/")[1]
    try:
        minio_client.put_object(
            bucket_thumbnails, 
            file_name,
            img.file, 
            file_size, 
            img.content_type)
        publicUrl = MinioBaseUrl+bucket_thumbnails+"/"+parse.quote(file_name)
    except InvalidResponseError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err.message
        )
    
    user.pic_url = publicUrl
    await user.save()

    return UserResponse(
        username=user.username,
        email=user.email,
        pic_url=user.pic_url
    )
