import os
from passlib.context import CryptContext
from fastapi import status, HTTPException
from urllib import parse
from minio import InvalidResponseError
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


# Add img to minio
def add_minio(img, user, item):
    print(item)
    if img.content_type not in Allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid type of file"
        )

    file_size = os.fstat(img.file.fileno()).st_size
    if item:
        file_name = user.username+"/"+str(item.id)+"." +img.content_type.split("/")[1]
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


def delete_minio(url: str = None, file_name: str = None):
    if url:
        obj_name = url.split("/")[4]
    else:
        obj_name = file_name

    minio_client.remove_object(bucket, obj_name)
