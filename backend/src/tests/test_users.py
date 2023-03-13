from datetime import datetime
import pytest
from httpx import AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient

from src.config.database import startDB
from src.config.settings import settings
from src.utils import hash_password, verify_password
from ..models.user import User, Privileges


def users():
    list = []
    names = ["Joaquim", "Jones", "John", "The_dude"]
    for idx, n in enumerate(names):
        user = User(
            username=n,
            email=n+"@gmail.com",
            password=hash_password("testpassword"),
            verified=(idx % 2 != 0),
            privileges=idx,
            created_at=datetime.utcnow()
        )
        list.append(user)
    return list


@pytest.fixture(scope='module')
async def test_db():
    await startDB()
    yield
    # clean up database after test
    client = AsyncIOMotorClient(settings.DATABASE_URL)
    await client.drop_database(client.db_name)


# TODO - test diferent filtering options
# Get users
@pytest.mark.anyio
async def test_get_all_users(test_db, client: AsyncClient):

    users_list = users()

    response = await client.get("/users/")

    assert response.status_code == 200
    list = response.json()
    assert len(list) == 0

    await users_list[0].create()

    response = await client.get("/users/")
    assert response.status_code == 200
    list = response.json()
    assert len(list) == 1

    await users_list[1].create()
    await users_list[2].create()

    response = await client.get("/users/")
    assert response.status_code == 200
    list = response.json()
    assert len(list) == 3

    await User.delete_all()


@pytest.mark.anyio
async def test_get_user(test_db, client: AsyncClient):

    users_list = users()

    await users_list[0].create()

    response = await client.get("/users/"+users_list[0].username)

    assert response.status_code == 200
    assert response.json()["username"] == users_list[0].username
    assert response.json()["email"] == users_list[0].email
    assert response.json()["verified"] == users_list[0].verified
    assert response.json()["privileges"] == users_list[0].privileges

    await users_list[0].delete()


@pytest.mark.anyio
async def test_get_non_existing_user(test_db, client: AsyncClient):

    response = await client.get("/users/nonexistinguser")

    assert response.status_code == 404
    assert response.json()["detail"] == "User does not exist"


# Delete
@pytest.mark.anyio
async def test_delete_self_user_verified(test_db, client: AsyncClient):

    users_list = users()
    await users_list[1].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": users_list[1].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.delete(
        "/users/"+users_list[1].username
    )

    assert response.status_code == 204

    user = await User.find_one(User.username == users_list[1].username)
    assert not user


@pytest.mark.anyio
async def test_delete_self_user_not_verified(test_db, client: AsyncClient):

    users_list = users()
    await users_list[0].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": users_list[0].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.delete(
        "/users/"+users_list[0].username
    )

    assert response.status_code == 204

    user = await User.find_one(User.username == users_list[0].username)
    assert not user


@pytest.mark.anyio
async def test_delete_other_user_admin(test_db, client: AsyncClient):

    users_list = users()

    # Requesting Delete
    await users_list[3].create()

    # To be Deleted
    await users_list[0].create()

    print(users_list[3])

    response = await client.post(
        "/auth/login",
        data={
            "username": users_list[3].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.delete(
        "/users/"+users_list[0].username
    )

    assert response.status_code == 204
    user = await User.find_one(User.username == users_list[0].username)
    assert not user

    await User.delete_all()


@pytest.mark.anyio
async def test_user_delete_other_user(test_db, client: AsyncClient):
    users_list = users()

    # Verified
    await users_list[0].create()
    # Not verified
    await users_list[1].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": users_list[1].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.delete(
        "/users/"+users_list[0].username
    )

    assert response.status_code == 401
    assert response.json()[
        "detail"] == "Need admin privilege to delete another user"
    user = User.find_one(User.username == users_list[0].username)
    assert user

    response = await client.post(
        "/auth/login",
        data={
            "username": users_list[0].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.delete("/users/"+users_list[1].username)

    assert response.status_code == 401
    assert response.json()[
        "detail"] == "Need admin privilege to delete another user"
    user = User.find_one(User.username == users_list[1].username)
    assert user


@pytest.mark.anyio
async def test_user_delete_non_existing_user(test_db, client: AsyncClient):

    users_list = users()
    await users_list[3].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": users_list[3].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.delete(
        "/users/unknowuser"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

    await User.delete_all()


# Verify
@pytest.mark.anyio
async def test_user_verify(test_db, client: AsyncClient):
    users_list = users()

    await users_list[3].create()
    await users_list[0].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": users_list[3].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.patch("/users/"+users_list[0].username+"/verify")

    assert response.status_code == 200
    user = await User.find_one(User.username == users_list[0].username)
    assert user.verified

    await User.delete_all()


@pytest.mark.anyio
async def test_already_verified_user(test_db, client: AsyncClient):

    users_list = users()

    await users_list[3].create()
    await users_list[1].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": users_list[3].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.patch("/users/"+users_list[1].username+"/verify")

    assert response.status_code == 400
    assert response.json()["detail"] == "User is already verified"

    await User.delete_all()


@pytest.mark.anyio
async def test_non_admin_verify(test_db, client: AsyncClient):

    users_list = users()

    await users_list[0].create()
    await users_list[2].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": users_list[0].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    # Non admin-User tries to verify itself
    response = await client.patch("/users/"+users_list[0].username+"/verify")
    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    # Non admin-User tries to verify others
    response = await client.patch("/users/"+users_list[2].username+"/verify")
    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    await User.delete_all()


@pytest.mark.anyio
async def test_verify_non_existing_user(test_db, client: AsyncClient):

    user_list = users()

    await user_list[3].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_list[3].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.patch("/users/nonexistinguser/verify")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

    await User.delete_all()


# Privileges
@pytest.mark.anyio
async def test_user_privilege_change(test_db, client: AsyncClient):

    user_list = users()
    await user_list[3].create()
    await user_list[1].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_list[3].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.patch(
        "/users/"+user_list[1].username+"/privileges/pending")
    assert response.status_code == 200

    user = await User.find_one(User.username == user_list[1].username)

    assert response.json()["username"] == user.username
    assert response.json()["verified"] == user.verified
    assert response.json()["privileges"] == user.privileges

    response = await client.patch(
        "/users/"+user_list[1].username+"/privileges/visitor")
    assert response.status_code == 200

    user = await User.find_one(User.username == user_list[1].username)

    assert response.json()["username"] == user.username
    assert response.json()["verified"] == user.verified
    assert response.json()["privileges"] == user.privileges

    response = await client.patch(
        "/users/"+user_list[1].username+"/privileges/creator")
    assert response.status_code == 200

    user = await User.find_one(User.username == user_list[1].username)

    assert response.json()["username"] == user.username
    assert response.json()["verified"] == user.verified
    assert response.json()["privileges"] == user.privileges

    response = await client.patch(
        "/users/"+user_list[1].username+"/privileges/admin")
    assert response.status_code == 200

    user = await User.find_one(User.username == user_list[1].username)

    assert response.json()["username"] == user.username
    assert response.json()["verified"] == user.verified
    assert response.json()["privileges"] == user.privileges

    await User.delete_all()


@pytest.mark.anyio
async def test_invalid_privilege(test_db, client: AsyncClient):

    user_list = users()

    await user_list[3].create()
    await user_list[1].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_list[3].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.patch(
        "/users/"+user_list[1].username+"/privileges/invalid")
    assert response.status_code == 400

    user = await User.find_one(User.username == user_list[1].username)
    assert user_list[1].privileges == user.privileges

    await User.delete_all()


@pytest.mark.anyio
async def test_privilege_non_existing_user(test_db, client: AsyncClient):
    user_list = users()

    await user_list[3].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_list[3].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.patch(
        "/users/invaliduser/privileges/invalid"
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "User does not exist"

    await User.delete_all()


@pytest.mark.anyio
async def test_privilege_unverified_user(test_db, client: AsyncClient):

    user_list = users()

    await user_list[3].create()
    await user_list[0].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_list[3].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.patch(
        "/users/"+user_list[0].username+"/privileges/invalid")
    assert response.status_code == 400
    assert response.json()["detail"] == "User not verified"

    user = await User.find_one(User.username == user_list[0].username)
    assert user_list[0].privileges == user.privileges

    await User.delete_all()


@pytest.mark.anyio
async def test_unauthorized_privilege_change(test_db, client: AsyncClient):
    user_list = users()

    await user_list[1].create()
    await user_list[2].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_list[2].username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.patch(
        "/users/"+user_list[1].username+"/privileges/invalid")
    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    user = await User.find_one(User.username == user_list[1].username)
    assert user_list[1].privileges == user.privileges

    await User.delete_all()
