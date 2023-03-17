from datetime import datetime
import pytest
from httpx import AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient

from src.config.database import startDB
from src.config.settings import settings
from src.utils import delete_minio, hash_password, get_user_media_list, clear_bucket
from src.tests.test_utils import login, logout
from ..models.user import Privileges, User
from ..config.settings import MinioBaseUrl
from ..config.storage import bucket, minio_client, default_url


@pytest.fixture(scope='module')
async def test_db():
    await startDB()
    yield
    # clean up database after test
    client = AsyncIOMotorClient(settings.DATABASE_URL)
    await client.drop_database(client.db_name)


@pytest.mark.anyio
async def test_init_var(test_db, client: AsyncClient):

    global user_not_verified
    global user_visitor
    global user_creator
    global user_admin

    user_not_verified = User(
        username="not_verified",
        email="not_verified@gmail.com",
        password=hash_password("testpassword"),
        verified=False,
        pic_url=default_url,
        privileges=Privileges.PENDING,
        created_at=datetime.utcnow()
    )

    user_visitor = User(
        username="visitor",
        email="visitor@gmail.com",
        password=hash_password("testpassword"),
        verified=True,
        pic_url=default_url,
        privileges=Privileges.VISITOR,
        created_at=datetime.utcnow()
    )

    user_creator = User(
        username="creator",
        email="creator@gmail.com",
        password=hash_password("testpassword"),
        verified=True,
        pic_url=default_url,
        privileges=Privileges.CREATOR,
        created_at=datetime.utcnow()
    )

    user_admin = User(
        username="admin",
        email="admin@gmail.com",
        password=hash_password("testpassword"),
        verified=True,
        pic_url=default_url,
        privileges=Privileges.ADMIN,
        created_at=datetime.utcnow()
    )

    assert user_admin.username == "admin"
    assert user_creator.username == "creator"
    assert user_visitor.username == "visitor"
    assert user_not_verified.username == "not_verified"


"""
    Get Users
"""


@pytest.mark.anyio
async def test_get_all_users(test_db, client: AsyncClient):
    # Empty database
    response = await client.get("/users/")
    assert response.status_code == 200
    assert len(response.json()) == 0

    # Create one user
    await user_admin.create()
    response = await client.get("/users/")
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["username"] == "admin"

    # Create 2 more users
    await user_creator.create()
    await user_visitor.create()
    response = await client.get("/users/")
    assert response.status_code == 200
    assert len(response.json()) == 3

    # Assert that database is empty
    await User.delete_all()
    response = await client.get("/users/")
    assert response.status_code == 200
    assert len(response.json()) == 0


@pytest.mark.anyio
async def test_get_user(test_db, client: AsyncClient):
    await user_admin.create()
    response = await client.get("/users/"+user_admin.username)

    assert response.status_code == 200
    assert response.json()["username"] == user_admin.username
    assert response.json()["email"] == user_admin.email
    assert response.json()["verified"] == user_admin.verified
    assert response.json()["pic_url"] == user_admin.pic_url
    assert response.json()["privileges"] == user_admin.privileges

    await User.delete_all()


@pytest.mark.anyio
async def test_get_non_existing_user(test_db, client: AsyncClient):
    await User.insert_many([user_admin, user_creator, user_visitor, user_not_verified])
    response = await client.get("/users/")
    assert response.status_code == 200
    assert len(response.json()) == 4

    user = await User.find_one(User.username == "johnDoe")
    assert not user

    response = await client.get("/users/johnDoe")
    assert response.status_code == 404
    assert response.json()["detail"] == "User does not exist"

    await User.delete_all()


"""
    Delete users
"""


@pytest.mark.anyio
async def test_delete_self_user(test_db, client: AsyncClient):

    await user_not_verified.create()
    await user_creator.create()

    # Not verified
    await login(user_not_verified.username, "testpassword", client)

    response = await client.delete("/users/"+user_not_verified.username)
    assert response.status_code == 204
    assert not response.text
    deleted_user = await User.find_one(User.username == user_not_verified.username)
    assert not deleted_user

    # Verified
    await login(user_creator.username, "testpassword", client)

    response = await client.delete("/users/"+user_creator.username)
    assert response.status_code == 204
    assert not response.text
    deleted_user = await User.find_one(User.username == user_creator.username)
    assert not deleted_user
    assert len(await User.find_many().to_list()) == 0


@pytest.mark.anyio
async def test_admin_delete_user(test_db, client: AsyncClient):
    await user_admin.create()
    await user_creator.create()

    await login(user_admin.username, "testpassword", client)

    response = await client.delete("/users/"+user_creator.username)
    assert response.status_code == 204
    assert not response.text

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_user_delete_user(test_db, client: AsyncClient):
    await user_creator.create()
    await user_not_verified.create()

    await login(user_creator.username, "testpassword", client)

    response = await client.delete("/users/"+user_not_verified.username)
    assert response.status_code == 401
    assert response.json()[
        "detail"] == "Need admin privilege to delete another user"

    await logout(client)

    await login(user_not_verified.username, "testpassword", client)

    response = await client.delete("/users/"+user_creator.username)
    assert response.status_code == 401
    assert response.json()[
        "detail"] == "Need admin privilege to delete another user"

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_delete_non_existing_user(test_db, client: AsyncClient):
    await user_admin.create()

    await login(user_admin.username, "testpassword", client)

    user = await User.find_one(User.username == "johnDoe")
    assert not user

    response = await client.delete("/users/johnDoe")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

    await logout(client)

    await User.delete_all()


"""
    Verify
"""


@pytest.mark.anyio
async def test_user_verify(test_db, client: AsyncClient):
    await user_admin.create()
    await user_not_verified.create()

    await login(user_admin.username, "testpassword", client)

    response = await client.patch(
        "/users/"+user_not_verified.username+"/verify",
    )
    assert response.status_code == 200
    user = await User.find_one(User.username == user_not_verified.username)
    assert user.verified

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_already_verified_user(test_db, client: AsyncClient):

    await user_admin.create()
    await user_visitor.create()

    await login(user_admin.username, "testpassword", client)

    response = await client.patch("/users/"+user_visitor.username+"/verify")
    assert response.status_code == 400
    assert response.json()["detail"] == "User is already verified"

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_non_admin_verify(test_db, client: AsyncClient):
    await user_creator.create()
    await user_not_verified.create()

    await login(user_creator.username, "testpassword", client)

    # User tries to verify himself
    response = await client.patch("/users/"+user_creator.username+"/verify")
    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    # User tries to verify other user
    response = await client.patch("/users/"+user_not_verified.username+"/verify")
    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_verify_not_user(test_db, client: AsyncClient):
    await user_admin.create()

    await login(user_admin.username, "testpassword", client)

    user = await User.find_one(User.username == "johnDoe")
    assert not user

    response = await client.patch("/users/johnDoe/verify")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

    await logout(client)

    await User.delete_all()


"""
    Privileges
"""


@pytest.mark.anyio
async def test_user_privilege_change(test_db, client: AsyncClient):
    await user_admin.create()
    await user_visitor.create()

    await login(user_admin.username, "password", client)

    # Pending
    response = await client.patch(
        "/users/"+user_visitor.username+"/privileges/pending"
    )
    assert response.status_code == 200
    user = await User.find_one(User.username == user_visitor.username)
    assert response.json()["privileges"] == user.privileges
    assert user.privileges == Privileges.PENDING

    # Visitor
    response = await client.patch(
        "/users/"+user_visitor.username+"/privileges/visitor"
    )
    assert response.status_code == 200
    user = await User.find_one(User.username == user_visitor.username)
    assert response.json()["privileges"] == user.privileges
    assert user.privileges == Privileges.VISITOR

    # Creator
    response = await client.patch(
        "/users/"+user_visitor.username+"/privileges/creator"
    )
    assert response.status_code == 200
    user = await User.find_one(User.username == user_visitor.username)
    assert response.json()["privileges"] == user.privileges
    assert user.privileges == Privileges.CREATOR

    # Admin
    response = await client.patch(
        "/users/"+user_visitor.username+"/privileges/admin"
    )
    assert response.status_code == 200
    user = await User.find_one(User.username == user_visitor.username)
    assert response.json()["privileges"] == user.privileges
    assert user.privileges == Privileges.ADMIN

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_invalid_privilege(test_db, client: AsyncClient):
    await user_admin.create()
    await user_visitor.create()

    await login(user_admin.username, "testpassword", client)

    response = await client.patch("/users/"+user_visitor.username+"/privileges/invalid")
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid privilege"

    user = await User.find_one(User.username == user_visitor.username)
    assert user.privileges == user_visitor.privileges

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_privilege_not_user(test_db, client: AsyncClient):
    await user_admin.create()

    await login(user_admin.username, "testpassword", client)

    user = await User.find_one(User.username == "johnDoe")
    assert not user

    response = await client.patch("/users/johnDoe/privileges/creator")
    response.status_code == 404
    response.json()["detail"] == "User not found"

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_privilege_unverified_user(test_db, client: AsyncClient):
    await user_admin.create()
    await user_not_verified.create()

    await login(user_admin.username, "testpassword", client)

    user = await User.find_one(User.username == user_not_verified.username)
    assert not user.verified

    response = await client.patch(
        "/users/"+user_not_verified.username+"/privileges/admin"
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "User not verified"

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_unauthorized_privilege_change(test_db, client: AsyncClient):
    await user_creator.create()
    await user_visitor.create()

    await login(user_creator.username, "testpassword", client)

    # User changes privilege on itself
    response = await client.patch("/users/"+user_creator.username+"/privileges/admin")

    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    # User changes privilege on other user
    response = await client.patch("/users/"+user_visitor.username+"/privileges/creator")

    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_user_change_profile_pic(test_db, client: AsyncClient):
    await user_visitor.create()

    await login(user_visitor.username, "testpassword", client)

    # Test JPEG
    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+user_visitor.username+"/profile_pic", files=_files
    )
    print(response)
    assert response.status_code == 200
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_visitor.username+"/thumbnail.jpeg"

    # Test PNG
    file = "pizza.png"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+user_visitor.username+"/profile_pic", files=_files
    )
    assert response.status_code == 200
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_visitor.username+"/thumbnail.png"

    await logout(client)

    await User.delete_all()

"""
    Profile Picture change
"""


@pytest.mark.anyio
async def test_user_change_profile_pic(test_db, client: AsyncClient):

    await user_creator.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_creator.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    # Test JPEG
    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+user_creator.username+"/profile_pic", files=_files
    )
    print(response)
    assert response.status_code == 200
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_creator.username+"/thumbnail.jpeg"

    # Test PNG
    file = "pizza.png"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+user_creator.username+"/profile_pic", files=_files
    )
    assert response.status_code == 200
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_creator.username+"/thumbnail.png"

    # Assert, after insertion, user thumbnail is just one
    list = get_user_media_list(user_creator.username)
    assert len(list) == 1

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    clear_bucket()

    await User.delete_all()


@pytest.mark.anyio
async def test_admin_change_other_profile_pic(test_db, client: AsyncClient):
    await user_admin.create()
    await user_visitor.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    # Test JPEG
    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+user_visitor.username+"/profile_pic", files=_files
    )
    print(response)
    assert response.status_code == 200
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_visitor.username+"/thumbnail.jpeg"

    # Assert, after insertion, user thumbnail is just one
    list = get_user_media_list(user_visitor.username)
    assert len(list) == 1

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    clear_bucket()

    await User.delete_all()


@pytest.mark.anyio
async def test_incorrect_type_profile_pic(test_db, client: AsyncClient):
    await user_creator.create()
    response = await client.post(
        "/auth/login",
        data={
            "username": user_creator.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    # Test unsuported type
    file = "conftest.py"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+user_creator.username+"/profile_pic", files=_files
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid type of file"
    user = await User.find_one(User.username == user_creator.username)
    assert user.pic_url == default_url

    await User.delete_all()


@pytest.mark.anyio
async def test_not_user_change_profile_pic(test_db, client: AsyncClient):

    await user_admin.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
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
    user = await User.find_one(User.username == "non_existing_username")
    assert not user

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_unverified_user_change_profile_pic(test_db, client: AsyncClient):
    await user_not_verified.create()
    response = await client.post(
        "/auth/login",
        data={
            "username": user_not_verified.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+user_not_verified.username+"/profile_pic", files=_files
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "You're not verified"
    user = await User.find_one(User.username == user_not_verified.username)
    assert user.pic_url == default_url

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_non_admin_change_other_profile_pic(test_db, client: AsyncClient):
    await user_creator.create()
    await user_visitor.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_creator.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+user_visitor.username+"/profile_pic", files=_files
    )

    assert response.status_code == 401
    assert response.json()[
        "detail"] == "Need admin privilege to change another's user profile picture"

    user = await User.find_one(User.username == user_visitor.username)
    assert user.pic_url == default_url

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()
