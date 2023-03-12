from httpx import AsyncClient
import pytest
from ..main import app
from ..models.user import User, Privileges
from fastapi.testclient import TestClient

base_url = "http://localhost:8000/api/auth"

pytest_plugins = ('pytest_asyncio',)
"""

@pytest.mark.asyncio
async def test_create_user():
    async with AsyncClient(app=app, base_url=base_url) as client:
        # create a new admin user
        response = await client.post(
            "/register",
            data={
                "username": "adminuser",
                "email": "adminuser@example.com",
                "password": "adminpassword"
            }
        )
        assert response.status_code == 201
        assert response.json() == {
            "id": response.json()["id"],
            "username": "adminuser",
            "email": "adminuser@example.com",
            "verified": True,
            "privileges": "admin"
        }

        # check that the user was created in the database
        user = await User.find_one(User.username == "adminuser")
        assert user is not None
        assert user.email == "adminuser@example.com"
        assert user.password is not None
        assert user.privileges == Privileges.ADMIN

        # create a second user with the same email (should return 409 conflict)
        response = await client.post(
            "/register",
            data={
                "username": "testuser",
                "email": "adminuser@example.com",
                "password": "testpassword"
            }
        )
        assert response.status_code == 409
        assert response.json() == {
            "detail": "Email or username already taken"
        }

        # create a second user with a different email
        response = await client.post(
            "/register",
            data={
                "username": "testuser",
                "email": "testuser@example.com",
                "password": "testpassword"
            }
        )
        assert response.status_code == 201
        assert response.json() == {
            "id": response.json()["id"],
            "username": "testuser",
            "email": "testuser@example.com",
            "verified": False,
            "privileges": "pending"
        }

        # check that the second user was created in the database
        user = await User.find_one(User.username == "testuser")
        assert user is not None
        assert user.email == "testuser@example.com"
        assert user.password is not None
        assert user.privileges == Privileges.PENDING

"""

# def test_read_items():
#     with TestClient(app) as client:
#         response = client.get(base_url+"/register")
