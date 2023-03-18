import os
from passlib.context import CryptContext
from fastapi import status, HTTPException
from urllib import parse
from minio import InvalidResponseError, S3Error
from pydantic import BaseModel

from src.config.settings import Allowed_types, MinioBaseUrl
from src.config.storage import minio_client, bucket
import logging
logging.basicConfig(level=logging.DEBUG)

pwd_context = CryptContext(
    schemes=["bcrypt", "sha256_crypt"],
    sha256_crypt__rounds=5000,
    deprecated="auto"
)


class ErrorMessage(BaseModel):
    detail: str


class SuccessMessage(BaseModel):
    status: str


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)

"""
    Minio file_structure:
        - Files are either jpg or png
        - Each user get's a folder with it's name on creation of content (profile_pic or item)
        bucket/username/thumbnail.jpg (for profile picture)
        bucket/username/item_id.jpg
"""
# Add img to minio
def add_minio(img, user, item):

    if img.content_type not in Allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid type of file"
        )

    file_size = os.fstat(img.file.fileno()).st_size
    if item:
        file_name = user.username+"/" + \
            str(item.id)+"." + img.content_type.split("/")[1]
        print(file_name)
    else:
        file_name = user.username+"/thumbnail."+img.content_type.split("/")[1]

    try:
        minio_client.put_object(
            bucket,
            file_name,
            img.file,
            file_size,
            img.content_type
        )
        publicUrl = MinioBaseUrl+bucket+"/"+parse.quote(file_name)
        return publicUrl
    except InvalidResponseError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err.message
        )


def delete_user_media(username: str):
    objects_to_delete = minio_client.list_objects(
        bucket, prefix=username, recursive=True)
    for obj in objects_to_delete:
        print(obj.object_name)
        minio_client.remove_object(bucket, obj.object_name)


def get_user_media_list(username: str):
    objects = minio_client.list_objects(
        bucket, prefix=username, recursive=True)
    list = []

    for obj in objects:
        list.append(obj.object_name)
    return list


def delete_minio(url: str = None, file_name: str = None):
    if url:
        obj_name = url.split("/")[4]+"/"+url.split("/")[5]
    else:
        obj_name = file_name
    try:
        obj = minio_client.get_object(bucket, obj_name)
        minio_client.remove_object(bucket, obj_name)
        return obj

    except S3Error as err:
        return None

    except InvalidResponseError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=err.message
        )


def clear_bucket():
    objects = minio_client.list_objects(bucket, recursive=True)
    for obj in objects:
        delete_minio(file_name=obj.object_name)
        print(obj.object_name)

    objects = minio_client.list_objects(bucket, recursive=True)

    assert len([obj.object_name for obj in objects]) == 0
