from datetime import datetime
import pytest
from httpx import AsyncClient
from src.config.database import startDB

from src.config.settings import settings

from ..main import app
from ..models.user import User, Privileges
from motor.motor_asyncio import AsyncIOMotorClient


@pytest.fixture(scope='module')
async def test_db():
    await startDB()
    yield
    # clean up database after test
    client = AsyncIOMotorClient(settings.DATABASE_URL)
    await client.drop_database(client.db_name)


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
