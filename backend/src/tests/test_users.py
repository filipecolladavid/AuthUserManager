from datetime import datetime
import pytest
from httpx import AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient

from src.config.database import startDB
from src.config.settings import settings
from src.utils import delete_minio, hash_password, verify_password
from ..models.user import User
from ..config.settings import MinioBaseUrl
from ..config.storage import bucket, minio_client


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
        "/users/"+user_list[2].username+"/privileges/admin")
    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    user = await User.find_one(User.username == user_list[2].username)
    assert user_list[2].privileges == user.privileges

    await User.delete_all()


# Profile picture change
@pytest.mark.anyio
async def test_user_change_profile_pic(test_db, client: AsyncClient):
    list_users = users()
    await list_users[1].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": list_users[1].username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    # Test JPEG
    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+list_users[1].username+"/profile_pic", files=_files
    )
    print(response)
    assert response.status_code == 200
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+list_users[1].username+"/thumbnail.jpeg"

    # Test PNG
    file = "pizza.png"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+list_users[1].username+"/profile_pic", files=_files
    )
    assert response.status_code == 200
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+list_users[1].username+"/thumbnail.png"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_admin_change_other_profile_pic(test_db, client: AsyncClient):
    list_users = users()
    await list_users[3].create()
    await list_users[1].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": list_users[3].username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    # Test JPEG
    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+list_users[1].username+"/profile_pic", files=_files
    )
    print(response.json())
    assert response.status_code == 200
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+list_users[1].username+"/thumbnail.jpeg"

    # Test PNG
    file = "pizza.png"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+list_users[1].username+"/profile_pic", files=_files
    )
    assert response.status_code == 200
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+list_users[1].username+"/thumbnail.png"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_incorrect_type_profile_pic(test_db, client: AsyncClient):
    list_users = users()

    await list_users[1].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": list_users[1].username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    # Test unsuported type
    file = "conftest.py"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+list_users[1].username+"/profile_pic", files=_files
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid type of file"

    await User.delete_all()


@pytest.mark.anyio
async def test_change_non_user_profile_pic(test_db, client: AsyncClient):
    list_users = users()
    await list_users[3].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": list_users[3].username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/non_existing_username/profile_pic", files=_files
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

    await User.delete_all()


@pytest.mark.anyio
async def test_change_unverified_user(test_db, client: AsyncClient):
    list_users = users()
    await list_users[0].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": list_users[0].username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/non_existing_username/profile_pic", files=_files
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "You're not verified"


@pytest.mark.anyio
async def test_non_admin_change_other_profile_pic(test_db, client: AsyncClient):
    list_users = users()
    await list_users[1].create()
    await list_users[3].create()

    response = await client.post(
        "/auth/login",
        data={
            "username": list_users[1].username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+list_users[3].username+"/profile_pic", files=_files
    )

    assert response.status_code == 401
    assert response.json()[
        "detail"] == "Need admin privilege to change another's user profile picture"


# Delete all minio items
@pytest.mark.anyio
async def test_clear_bucket(test_db, client: AsyncClient):
    objects = minio_client.list_objects(bucket, recursive=True)
    for obj in objects:
        delete_minio(file_name=obj.object_name)

    objects = minio_client.list_objects(bucket, recursive=True)

    assert len([obj.object_name for obj in objects]) == 0
