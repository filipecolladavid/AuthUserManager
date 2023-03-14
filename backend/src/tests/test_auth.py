from datetime import datetime
import pytest
from httpx import AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient

from src.config.database import startDB
from src.config.settings import settings
from src.utils import hash_password, verify_password
from ..models.user import User, Privileges


@pytest.fixture(scope='module')
async def test_db():
    await startDB()
    client = AsyncIOMotorClient(settings.DATABASE_URL)
    yield client
    
    # clean up database after test
    await client.drop_database(client.db_name)


# Register - During test db has 1 user admin others are removed
@pytest.mark.anyio
async def test_create_first_user_as_admin(test_db, client: AsyncClient):

    response = await client.post(
        "auth/register",
        data={
            "email": "admin@example.com",
            "username": "admin",
            "password": "adminpassword"
        }
    )

    assert response.status_code == 201
    assert response.json()["username"] == "admin"
    assert response.json()["email"] == "admin@example.com"
    assert response.json()["verified"] == True
    assert response.json()["privileges"] == Privileges.ADMIN


@pytest.mark.anyio
async def test_create_user_init_verified_privilege_status(test_db, client: AsyncClient):
    response = await client.post(
        "auth/register",
        data={
            "email": "user@example.com",
            "username": "user",
            "password": "userpassword"
        }
    )
    assert response.status_code == 201
    assert response.json()["username"] == "user"
    assert response.json()["email"] == "user@example.com"
    assert response.json()["verified"] == False
    assert response.json()["privileges"] == Privileges.PENDING

    user = await User.find_one(User.username == "user")
    await user.delete()


@pytest.mark.anyio
async def test_create_user_with_existing_email(test_db, client: AsyncClient):

    # Create a user with a username
    user = User(
        username="testuser",
        email="test@example.com",
        password="testpassword",
        verified=False,
        privileges=Privileges.PENDING,
        created_at=datetime.utcnow()
    )

    await user.create()

    response = await client.post(
        "auth/register",
        data={
            "email": "test@example.com",
            "username": "testuser2",
            "password": "testpassword"
        }
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Email or username already taken"

    await user.delete()


@pytest.mark.anyio
async def test_create_user_with_existing_username(test_db, client: AsyncClient):
    # Create a user with a username
    user = User(
        username="testuser",
        email="test@example.com",
        password="testpassword",
        verified=True,
        privileges=Privileges.VISITOR,
        created_at=datetime.utcnow()
    )

    await user.create()

    response = await client.post(
        "auth/register",
        data={
            "email": "testuser2@example.com",
            "username": "testuser",
            "password": "testpassword"
        }
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Email or username already taken"

    await user.delete()


# Password test
def test_verify_password():
    password = "testpassword"
    hashed_password = hash_password(password)
    assert verify_password(password, hashed_password) == True
    assert verify_password("wrongpassword", hashed_password) == False


# Login
@pytest.mark.anyio
async def test_login_with_correct_credentials(test_db, client: AsyncClient):

    # Create a user with correct credentials
    user = User(
        username="testuser",
        email="testuser@gmail.com".lower(),
        password=hash_password("testpassword"),
        verified=False,
        privileges=Privileges.PENDING,
        created_at=datetime.utcnow()
    )

    await user.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )

    # Assert that the response has a 200 status code
    assert response.status_code == 200

    # Assert that the response has an access_token field
    assert "access_token" in response.json()

    await user.delete()


@pytest.mark.anyio
async def test_login_with_incorrect_password(test_db, client: AsyncClient):
    # Create a user with incorrect password
    user = User(
        username="testuser",
        email="test@example.com",
        password=hash_password("testpassword"),
        verified=True,
        privileges=Privileges.VISITOR,
        created_at=datetime.utcnow()
    )
    await user.create()

    # Make a request to the login endpoint with incorrect password
    response = await client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "wrongpassword"
        }
    )

    # Assert that the response has a 403 status code
    assert response.status_code == 403

    # Assert that the response has a detail field indicating wrong credentials
    assert response.json()["detail"] == "Incorrect username or password"

    await user.delete()


@pytest.mark.anyio
async def test_login_with_non_user(test_db, client: AsyncClient):

    # Make a request to the login endpoint with incorrect password
    response = await client.post(
        "/auth/login",
        data={
            "username": "notanuser",
            "password": "wrongpassword"
        }
    )

    # Assert that the response has a 404 status code
    assert response.status_code == 404

    # Assert that the response has a detail field indicating user not found
    assert response.json()["detail"] == "User not found"


# TODO
# Logout
# Refresh token