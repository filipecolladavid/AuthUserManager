import os
from typing import List
from fastapi import APIRouter, Depends, UploadFile, status, HTTPException
from urllib import parse
from minio import InvalidResponseError

from src.config.settings import Allowed_types, MinioBaseUrl
from src.config.storage import minio_client, bucket
from src.utils import add_minio

from ..models.user import User, UserResponse, Privileges
from .. import oauth2

router = APIRouter()


# Get all users
@router.get('/', response_model=List[UserResponse])
async def get_all(user_id: str = Depends(oauth2.require_admin)):
    # Find all documents in the collection
    all_users_cursor = User.find({})

    return await all_users_cursor.to_list(length=None)


# Get current logged in user
@router.get('/me', response_model=UserResponse)
async def get_me(user_id: str = Depends(oauth2.require_user)):
    return await User.get(str(user_id))


# Get user by username
@router.get('/{username}', response_model=UserResponse)
async def get_user_info(username: str, user_id: str = Depends(oauth2.require_admin)):
    user = await User.find_one(User.username == username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='User does not exist',
        )
    return user


# Delete user
@router.delete('/{username}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(username: str, user_id: str = Depends(oauth2.require_user)):
    # For deletion
    user = await User.find_one(User.username == username)

    # Requesting the deletion
    req_user = await User.get(str(user_id))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if req_user.privileges < Privileges.ADMIN and str(user.id) != str(user_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Need admin privilege to delete another user",
        )

    await user.delete()

    return status.HTTP_204_NO_CONTENT


# Verify user - requires admin (3) privilege
@router.patch('/{username}/verify', response_model=UserResponse)
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


# Change user's privilige - requires admin (3) privilege
@router.patch('/{username}/privileges', response_model=UserResponse)
async def change_user_privileges(username: str, privileges: str, user_id: str = Depends(oauth2.require_admin)):

    user = await User.find_one(User.username == username)

    admins = User.find(User.privileges == 3)
    admins = await admins.to_list(length=None)
    print(len(admins))
    if len(admins) == 1 and privileges.lower() != "admin": 
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Can't change admin status while being the only admin"
        )
    

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

    db_privileges = ""

    if privileges.lower() == "admin":
        db_privileges = Privileges.ADMIN
    elif privileges.lower() == "creator":
        db_privileges = Privileges.CREATOR
    elif privileges.lower() == "pending":
        db_privileges = Privileges.PENDING
    elif privileges.lower() == "visitor":
        db_privileges = Privileges.VISITOR
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid privilege",
        )

    user.privileges = db_privileges

    await user.save()

    return UserResponse(
        username=user.username,
        email=user.email,
        verified=user.verified,
        privileges=user.privileges,
        created_at=user.created_at,
        pic_url=str(user.pic_url),
    )


# Changes user's profile picture - requires admin (3) privilege to change other user's profile pictures
@router.put('/{username}/profile_pic', response_model=UserResponse)
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

    user.pic_url = add_minio(img=img,user=user,item=None)

    await user.save()

    return user
