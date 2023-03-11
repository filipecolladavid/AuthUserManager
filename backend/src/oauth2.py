import base64
from typing import List
from fastapi import Depends, HTTPException, status
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel

from .models.user import Privileges, User

from .config.settings import settings


class Settings(BaseModel):
    authjwt_algorithm: str = settings.JWT_ALGORITHM
    authjwt_decode_algorithms: List[str] = [settings.JWT_ALGORITHM]
    authjwt_token_location: set = {'cookies', 'headers'}
    authjwt_access_cookie_key: str = 'access_token'
    authjwt_refresh_cookie_key: str = 'refresh_token'
    authjwt_cookie_csrf_protect: bool = False
    authjwt_public_key: str = base64.b64decode(
        settings.JWT_PUBLIC_KEY).decode('utf-8')
    authjwt_private_key: str = base64.b64decode(
        settings.JWT_PRIVATE_KEY).decode('utf-8')


@AuthJWT.load_config
def get_config():
    return Settings()


class NotVerified(Exception):
    pass


class UserNotFound(Exception):
    pass


class NotCreator(Exception):
    pass


class Unauthorized(Exception):
    pass


async def require_admin(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
        user_id = Authorize.get_jwt_subject()

        user = await User.get(str(user_id))

        if not user:
            raise UserNotFound('User not found')
        if user.privileges < Privileges.ADMIN:
            raise Unauthorized('This action requires admin privileges')
        if not user.verified:
            raise NotVerified('You are not verified')

    except Exception as e:
        error = e.__class__.__name__
        print(e)
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='You are not logged in'
            )
        if error == 'UserNotFound':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='User no longer exist'
            )
        if error == 'Unauthorized':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='This action requires admin privileges'
            )
        if error == 'NotVerified':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="You're not verified"
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Token is invalid or has expired')

    return user_id


async def require_user(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
        user_id = Authorize.get_jwt_subject()

        user = await User.get(str(user_id))

        if not user:
            raise UserNotFound('User no longer exists')

        if not user.verified:
            raise NotVerified('You are not verified')

    except Exception as e:
        error = e.__class__.__name__
        print(e)
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='You are not logged in')
        if error == 'UserNotFound':
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail='User no longer exist')
        if error == 'NotVerified':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Please verify your account')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Token is invalid or has expired')
    return user_id


async def require_creator(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
        user_id = Authorize.get_jwt_subject()

        user = await User.get(str(user_id))

        if not user:
            raise UserNotFound('User no longer exists')

        if not user.verified:
            raise NotVerified('You are not verified')

        if user.privileges < Privileges.CREATOR:
            raise NotCreator('You need to be a creator to create a post')

    except Exception as e:
        error = e.__class__.__name__
        print(e)
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='You are not logged in'
            )
        if error == 'UserNotFound':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='User no longer exist'
            )
        if error == 'NotVerified':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Please verify your account'
            )
        if error == 'NotCreator':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="You need to be a creator to create a post"
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Token is invalid or has expired')
    return user_id


async def require_id(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
        user_id = Authorize.get_jwt_subject()

        user = await User.get(str(user_id))

    # For filtering posts can't raise HTTP exception if user doens't exist
    except Exception as e:
        return None
    
    return user_id
