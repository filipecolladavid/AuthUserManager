from datetime import datetime
import pytest
from httpx import AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient

from src.config.database import startDB
from src.config.settings import settings
from src.utils import delete_minio, hash_password
from ..models.user import Privileges, User
from ..config.settings import MinioBaseUrl
from ..config.storage import bucket, minio_client


# def users():
#     list = []
#     names = ["Joaquim", "Jones", "John", "The_dude"]
#     for idx, n in enumerate(names):
#         user = User(
#             username=n,
#             email=n+"@gmail.com",
#             password=hash_password("testpassword"),
#             verified=(idx % 2 != 0),
#             privileges=idx,
#             created_at=datetime.utcnow()
#         )
#         list.append(user)
#     return list


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
        privileges=Privileges.PENDING,
        created_at=datetime.utcnow()
    )

    user_visitor = User(
        username="visitor",
        email="visitor@gmail.com",
        password=hash_password("testpassword"),
        verified=True,
        privileges=Privileges.VISITOR,
        created_at=datetime.utcnow()
    )

    user_creator = User(
        username="creator",
        email="creator@gmail.com",
        password=hash_password("testpassword"),
        verified=True,
        privileges=Privileges.CREATOR,
        created_at=datetime.utcnow()
    )

    user_admin = User(
        username="admin",
        email="admin@gmail.com",
        password=hash_password("testpassword"),
        verified=True,
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
    response = await client.post(
        "/auth/login",
        data={
            "username": user_not_verified.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = await client.delete("/users/"+user_not_verified.username)
    assert response.status_code == 204
    assert not response.text
    deleted_user = await User.find_one(User.username == user_not_verified.username)
    assert not deleted_user

    # Verified
    response = await client.post(
        "/auth/login",
        data={
            "username": user_creator.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

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

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = await client.delete("/users/"+user_creator.username)
    assert response.status_code == 204
    assert not response.text

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_user_delete_user(test_db, client: AsyncClient):
    await user_creator.create()
    await user_not_verified.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_creator.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = await client.delete("/users/"+user_not_verified.username)
    assert response.status_code == 401
    assert response.json()[
        "detail"] == "Need admin privilege to delete another user"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    response = await client.post(
        "/auth/login",
        data={
            "username": user_not_verified.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = await client.delete("/users/"+user_creator.username)
    assert response.status_code == 401
    assert response.json()[
        "detail"] == "Need admin privilege to delete another user"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_delete_non_existing_user(test_db, client: AsyncClient):
    await user_admin.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    user = await User.find_one(User.username == "johnDoe")
    assert not user

    response = await client.delete("/users/johnDoe")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


"""
    Verify
"""


@pytest.mark.anyio
async def test_user_verify(test_db, client: AsyncClient):
    await user_admin.create()
    await user_not_verified.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = await client.patch(
        "/users/"+user_not_verified.username+"/verify",
    )
    assert response.status_code == 200
    user = await User.find_one(User.username == user_not_verified.username)
    assert user.verified

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_already_verified_user(test_db, client: AsyncClient):

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

    response = await client.patch("/users/"+user_visitor.username+"/verify")
    assert response.status_code == 400
    assert response.json()["detail"] == "User is already verified"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_non_admin_verify(test_db, client: AsyncClient):
    await user_creator.create()
    await user_not_verified.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_creator.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    # User tries to verify himself
    response = await client.patch("/users/"+user_creator.username+"/verify")
    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    # User tries to verify other user
    response = await client.patch("/users/"+user_not_verified.username+"/verify")
    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_verify_not_user(test_db, client: AsyncClient):
    await user_admin.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    user = await User.find_one(User.username == "johnDoe")
    assert not user

    response = await client.patch("/users/johnDoe/verify")
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


"""
    Privileges
"""


@pytest.mark.anyio
async def test_user_privilege_change(test_db, client: AsyncClient):
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

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_invalid_privilege(test_db, client: AsyncClient):
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

    response = await client.patch("/users/"+user_visitor.username+"/privileges/invalid")
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid privilege"

    user = await User.find_one(User.username == user_visitor.username)
    assert user.privileges == user_visitor.privileges

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_privilege_not_user(test_db, client: AsyncClient):
    await user_admin.create()

    response = await client.post(
        "auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    response.status_code == 200

    user = await User.find_one(User.username == "johnDoe")
    assert not user

    response = await client.patch("/users/johnDoe/privileges/creator")
    response.status_code == 404
    response.json()["detail"] == "User not found"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_privilege_unverified_user(test_db, client: AsyncClient):
    await user_admin.create()
    await user_not_verified.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    user = await User.find_one(User.username == user_not_verified.username)
    assert not user.verified

    response = await client.patch(
        "/users/"+user_not_verified.username+"/privileges/admin"
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "User not verified"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_unauthorized_privilege_change(test_db, client: AsyncClient):
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

    # User changes privilege on itself
    response = await client.patch("/users/"+user_creator.username+"/privileges/admin")

    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    # User changes privilege on other user
    response = await client.patch("/users/"+user_visitor.username+"/privileges/creator")

    assert response.status_code == 401
    assert response.json()["detail"] == "This action requires admin privileges"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


@pytest.mark.anyio
async def test_user_change_profile_pic(test_db, client: AsyncClient):
    await user_visitor.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_visitor.username,
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

    # Test PNG
    file = "pizza.png"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/users/"+user_visitor.username+"/profile_pic", files=_files
    )
    assert response.status_code == 200
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_visitor.username+"/thumbnail.png"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    await User.delete_all()


"""
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
"""
