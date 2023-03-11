from passlib.context import CryptContext
import os
from fastapi import status, HTTPException
from urllib import parse
from minio import InvalidResponseError
from pydantic import BaseModel

from src.config.settings import Allowed_types, MinioBaseUrl
from src.config.storage import minio_client, bucket

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class ErrorMessage(BaseModel):
    detail: str


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)

# Add img to minio
def add_minio(img, user, item):
    if img.content_type not in Allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid type of file"
        )
    
    file_size = os.fstat(img.file.fileno()).st_size
    if item:
        file_name = str(user.id)+"_"+str(item.id)+"." + \
            img.content_type.split("/")[1]
    else:
        file_name = file_name = str(
            user.id)+"_thumbnail."+img.content_type.split("/")[1]

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
# def is_valid_email(email: str) -> bool:
#     pat = "^[A-Z0-9_!#$%&'*+/=?`{|}~^-]+(?:\.[A-Z0-9_!#$%&'*+/=?`{|}~^-]+)*@[A-Z0-9-]+(?:\.[A-Z0-9-]+)*$"
#     print(re.match(pat,email))
#     if re.match(pat, email):
#         return True
#     return False
