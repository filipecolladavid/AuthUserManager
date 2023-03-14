from datetime import datetime, timedelta
from fastapi import APIRouter, Form, Response, status, Depends, HTTPException

from src import oauth2
from ..models.user import User, UserResponse, Privileges
from src.utils import ErrorMessage, hash_password, verify_password
from src.oauth2 import AuthJWT
from ..config.settings import settings


router = APIRouter()
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


# Register new User - First user get's admin status
@router.post(
    '/register',
    status_code=status.HTTP_201_CREATED,
    response_model=UserResponse,
    responses={
        409: {"model": ErrorMessage, "description": "Email or username already taken"}
    }
)
async def create_user(
        email: str = Form(...),
        username: str = Form(...),
        password: str = Form(...)
):

    new_user = ""

    size = await User.count()

    if (size == 0):
        new_user = User(
            username=username,
            email=email.lower(),
            password=hash_password(password),
            verified=True,
            privileges=Privileges.ADMIN,
            created_at=datetime.utcnow()
        )

    else:
        user_exists = await User.find_one(User.username == username)
        email_exists = await User.find_one(User.email == email)
        if user_exists or email_exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail='Email or username already taken'
            )

        new_user = User(
            username=username,
            email=email.lower(),
            password=hash_password(password),
            verified=False,
            privileges=Privileges.PENDING,
            created_at=datetime.utcnow()
        )
    await new_user.create()

    return new_user


# Sign In user
@router.post(
    '/login',
    status_code=status.HTTP_200_OK,
    responses={
        403: {"model": ErrorMessage, "description": "Wrong credentials"},
        404: {"model": ErrorMessage, "description": "User was not found"},
        200: {
            "description": "Sign in successfully",
            "content": {
                "application/json": {
                    "example": {"status": "success", "access_token": "access_token"}
                }
            },
        },
    },
)
async def login(response: Response, username: str = Form(...), password: str = Form(...), Authorize: AuthJWT = Depends()):
    user = await User.find_one(User.username == username)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail='User not found'
        )
    
    if not verify_password(password, user.password):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Incorrect username or password'
        )

    # Create access token
    access_token = Authorize.create_access_token(
        subject=str(user.id),
        expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN)
    )

    refresh_token = Authorize.create_refresh_token(
        subject=str(user.id),
        expires_time=timedelta(minutes=REFRESH_TOKEN_EXPIRES_IN)
    )

    # Store refresh and access tokens in cookie
    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('refresh_token', refresh_token,
                        REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')

    # Send both access
    return {'status': 'success', 'access_token': access_token}


# Refresh Acess Token
@router.get(
    '/refresh',
    responses={
        400: {"model": ErrorMessage, "description": "Invalid access Token"},
        401: {"model": ErrorMessage, "description": "Unauthorized"},
        404: {"model": ErrorMessage, "description": "User was not found"},
        200: {
            "description": "Access token refreshed",
            "content": {
                "application/json": {
                    "example": {"access_token": "access_token"}
                }
            },
        },
    },
)
async def refresh_token(response: Response, Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_refresh_token_required()

        user_id = Authorize.get_jwt_subject()

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Could not refresh access token'
            )

        user = await User.get(user_id)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail='The user belonging to this token no logger exist'
            )
        access_token = Authorize.create_access_token(
            subject=str(user.id),
            expires_time=timedelta(minutes=ACCESS_TOKEN_EXPIRES_IN)
        )
    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Please provide refresh token'
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )

    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')

    return {'access_token': access_token}


# Logout user
@router.get(
    '/logout',
    responses={
        401: {"model": ErrorMessage, "description": "Unauthorized"},
        404: {"model": ErrorMessage, "description": "User not found"},
        200: {
            "description": "Logged out",
            "content": {
                "application/json": {
                    "example": {"status": "success"}
                }
            },
        },
    }
)
def logout(response: Response, Authorize: AuthJWT = Depends(), user_id: str = Depends(oauth2.require_user)):
    Authorize.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)

    return {'status': 'success'}
