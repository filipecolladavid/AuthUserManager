from datetime import datetime
import pytest
from httpx import AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient

from src.config.database import startDB
from src.config.settings import MinioBaseUrl, settings
from src.config.storage import bucket
from src.models.items import Item, Visibility
from src.utils import hash_password, verify_password
from ..models.user import User, Privileges


def has_visibility_greater_than(arr, visibility):
    for item in arr:
        if item['visibility'] > visibility:
            return True
    return False


@pytest.fixture(scope='module')
async def test_db():
    await startDB()
    yield
    # clean up database after test
    client = AsyncIOMotorClient(settings.DATABASE_URL)
    await client.drop_database(client.db_name)


@pytest.mark.anyio
async def test_init_env(test_db, client: AsyncClient):

    global user_not_verified
    global user_visitor
    global user_creator
    global user_admin

    global item_all
    global item_users
    global item_admin

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

    await User.insert_many([user_not_verified, user_visitor, user_creator, user_admin])

    item_all = Item(
        title="A post for all",
        desc="A post for all",
        visibility=Visibility.ALL,
        author=user_admin.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid.png",
        created_at=datetime.utcnow()
    )

    item_users = Item(
        title="A post for users",
        desc="A post for users",
        visibility=Visibility.USERS,
        author=user_admin.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid_1.png",
        created_at=datetime.utcnow()
    )

    item_admin = Item(
        title="A post for admins",
        desc="A post for admins",
        visibility=Visibility.ADMIN,
        author=user_admin.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid_2.png",
        created_at=datetime.utcnow()
    )

    await Item.insert_many([item_all, item_users, item_admin])

    response = await client.get("/users/")

    assert response.status_code == 200
    assert len(response.json()) == 4

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.get("/items/")
    assert response.status_code == 200
    assert len(response.json()) == 3

    response = await client.get("/auth/logout")
    assert response.status_code == 200


# Get items
@pytest.mark.anyio
async def test_get_items_non_users(test_db, client: AsyncClient):

    """
        Testing for a non-user
    """
    response = await client.get("/items/")
    assert response.status_code == 200
    items = response.json()
    db_items = await Item.find(Item.visibility <= Visibility.ALL).to_list()

    assert len(db_items) == len(items)
    assert not has_visibility_greater_than(items, Visibility.ALL)

    """
        Testing for an user not verified
        Doesn't have access to posts restricted to users
    """
    response = await client.post(
        "/auth/login",
        data={
            "username": user_not_verified.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = await client.get("/items/")
    items = response.json()
    db_items = await Item.find(Item.visibility <= Visibility.ALL).to_list()

    assert len(db_items) == len(items)
    assert not has_visibility_greater_than(items, Visibility.ALL)

    response = await client.get("/auth/logout")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_get_items_users(test_db, client: AsyncClient):
    """
        Testing for an user with visitor privileges
        Access to posts restricted to users
    """
    response = await client.post(
        "/auth/login",
        data={
            "username": user_visitor.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = await client.get("/items/")
    items = response.json()
    db_items = await Item.find(Item.visibility <= Visibility.USERS).to_list()

    assert len(db_items) == len(items)
    assert not has_visibility_greater_than(items, Visibility.USERS)

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    """
        Testing for an user with creator privileges
        Access to posts restricted to users
    """
    response = await client.post(
        "/auth/login",
        data={
            "username": user_creator.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = await client.get("/items/")
    items = response.json()
    db_items = await Item.find(Item.visibility <= Visibility.USERS).to_list()

    assert len(db_items) == len(items)
    assert not has_visibility_greater_than(items, Visibility.USERS)

    response = await client.get("/auth/logout")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_get_items_admins(test_db, client: AsyncClient):
    """
        Testing for an user with creator privileges
        Access to posts restricted to users
    """
    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = await client.get("/items/")
    items = response.json()
    db_items = await Item.find(Item.visibility <= Visibility.ADMIN).to_list()

    assert len(db_items) == len(items)
    assert not has_visibility_greater_than(items, Visibility.ADMIN)

    response = await client.get("/auth/logout")
    assert response.status_code == 200


# Create item
@pytest.mark.anyio
async def test_create_item(test_db, client: AsyncClient):

    """
        Admin creates post
    """
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

    """
        With default visibility
    """
    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
        }
    )

    assert response.status_code == 200
    assert response.json()["title"] == "A title for a picture"
    assert response.json()["desc"] == "A desc for a picture"
    assert response.json()["visibility"] == Visibility.ALL
    assert response.json()["author"] == user_admin.username
    item_id = response.json()["_id"]
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_admin.username+"/"+item_id+".jpeg"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    """
        Creator creates post
    """
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

    """
        With default visibility
    """
    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
        }
    )

    assert response.status_code == 200
    assert response.json()["title"] == "A title for a picture"
    assert response.json()["desc"] == "A desc for a picture"
    assert response.json()["visibility"] == Visibility.ALL
    assert response.json()["author"] == user_creator.username
    item_id = response.json()["_id"]
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_creator.username+"/"+item_id+".jpeg"

    """
        With all visibility
    """
    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "all"
        }
    )

    assert response.status_code == 200
    assert response.json()["title"] == "A title for a picture"
    assert response.json()["desc"] == "A desc for a picture"
    assert response.json()["visibility"] == Visibility.ALL
    assert response.json()["author"] == user_creator.username
    item_id = response.json()["_id"]
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_creator.username+"/"+item_id+".jpeg"

    """
        With users visibility
    """
    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "users"
        }
    )

    assert response.status_code == 200
    assert response.json()["title"] == "A title for a picture"
    assert response.json()["desc"] == "A desc for a picture"
    assert response.json()["visibility"] == Visibility.USERS
    assert response.json()["author"] == user_creator.username
    item_id = response.json()["_id"]
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_creator.username+"/"+item_id+".jpeg"

    """
        With admin visibility
    """
    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "admin"
        }
    )

    assert response.status_code == 200
    assert response.json()["title"] == "A title for a picture"
    assert response.json()["desc"] == "A desc for a picture"
    assert response.json()["visibility"] == Visibility.ADMIN
    assert response.json()["author"] == user_creator.username
    item_id = response.json()["_id"]
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_creator.username+"/"+item_id+".jpeg"

    response = await client.get("/auth/logout")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_create_item_invalid_parameter(test_db, client: AsyncClient):
    response = await client.post(
        "/auth/login",
        data={
            "username": user_creator.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    """
        Invalid visibility
    """
    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "invalid"
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Visibility not valid"

    file = "conftest.py"
    _files = {'img': open(file, 'rb')}

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "all"
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid type of file"

    response = await client.get("/auth/logout")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_create_item_unauthorized(test_db, client: AsyncClient):

    """
        Not logged in
    """

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "all"
        }
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "You are not logged in"

    """
        Not verified
    """
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

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "all"
        }
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Please verify your account"

    response = await client.get("/auth/logout")
    assert response.status_code == 200

    """
        Not a creator
    """
    response = await client.post(
        "/auth/login",
        data={
            "username": user_visitor.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "all"
        }
    )

    assert response.status_code == 401
    assert response.json()[
        "detail"] == "You need to be a creator to create a post"


# Update
@pytest.mark.anyio
async def test_update_item(test_db, client: AsyncClient):

    user = await User.find_one(User.username == user_admin.username)

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    """
        Update all fields
    """

    file = "pizza.png"
    _files = {'img': open(file, 'rb')}

    item = await Item.find_one(Item.title == item_all.title)
    item_id = str(item.id)

    response = await client.put(
        "/items/"+item_id,
        files=_files,
        data={
            "title": "Changed title",
            "desc": "Changed desc",
            "visibility": "users",
        }
    )

    assert response.status_code == 200
    assert response.json()["title"] == "Changed title"
    assert response.json()["desc"] == "Changed desc"
    assert response.json()["visibility"] == Visibility.USERS
    assert response.json()["author"] == user.username
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_admin.username+"/"+item_id+".png"

    """
        Update just Title, Desc and Visibility
    """
    item = await Item.find_one(Item.title == "Changed title")
    item_id = str(item.id)

    response = await client.put(
        "/items/"+item_id,
        data={
            "title": "Changed title2",
            "desc": "Changed desc1",
            "visibility": "all"
        }
    )

    assert response.status_code == 200
    assert response.json()["title"] == "Changed title2"
    assert response.json()["desc"] == "Changed desc1"
    assert response.json()["visibility"] == Visibility.ALL
    assert response.json()["author"] == user.username
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_admin.username+"/"+item_id+".png"

    revert_item = Item(
        id=item.id,
        title="A post for all",
        desc="A post for all",
        visibility=Visibility.ALL,
        author=user_admin.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid.png",
        created_at=datetime.utcnow()
    )
    await revert_item.save()

    response = await client.get("/auth/logout")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_admin_update_other_user(test_db, client: AsyncClient):
    item = Item(
        title="Other user post",
        desc="Other user post",
        visibility=Visibility.ALL,
        author=user_creator.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid_3.png",
        created_at=datetime.utcnow()
    )
    await item.create()

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
        "/items/"+str(item.id),
        files=_files,
        data={
            "title": "Admin changed this post",
            "desc": "Admin changed this post",
            "visibility": "users"
        }
    )

    assert response.status_code == 200
    assert response.json()["title"] == "Admin changed this post"
    assert response.json()["desc"] == "Admin changed this post"
    assert response.json()["visibility"] == Visibility.USERS

    item_all = Item(
        id=item.id,
        title="A post for all",
        desc="A post for all",
        visibility=Visibility.ALL,
        author=user_admin.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid.png",
        created_at=datetime.utcnow()
    )
    await item_all.save()
    response = await client.get("/auth/logout")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_update_invalid_parameter(test_db, client: AsyncClient):
    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    """
        Invalid visibility
    """
    item = await Item.find_one(Item.title == item_all.title)
    item_id = str(item.id)

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/items/"+item_id,
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "invalid"
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Visibility not valid"

    file = "conftest.py"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/items/"+item_id,
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "all"
        }
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid type of file"


@pytest.mark.anyio
async def test_update_unauthorized(test_db, client: AsyncClient):
    response = await client.post(
        "/auth/login",
        data={
            "username": user_creator.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    item = await Item.find_one(Item.title == item_all.title)
    print(item)
    item_id = str(item.id)

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.put(
        "/items/"+item_id,
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "all"
        }
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "You can't change another users post"


# Delete
@pytest.mark.anyio
async def test_delete_post(test_db, client: AsyncClient):

    """
        Admin deletes post
    """
    custom_item = Item(
        title="Custom item",
        desc="Custom item",
        visibility=Visibility.ALL,
        author=user_admin.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid.png",
        created_at=datetime.utcnow()
    )
    item = await custom_item.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200
    item_id = str(item.id)
    response = await client.delete("/items/"+item_id)

    assert response.status_code == 204
    item = await Item.get(item_id)
    assert not item
    response = await client.get("/auth/logout")
    assert response.status_code == 200

    """
        Creator deletes post
    """
    custom_item = Item(
        title="Custom item",
        desc="Custom item",
        visibility=Visibility.ALL,
        author=user_creator.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid.png",
        created_at=datetime.utcnow()
    )

    item = await custom_item.create()
    response = await client.post(
        "/auth/login",
        data={
            "username": user_creator.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200
    item_id = str(item.id)
    response = await client.delete("/items/"+item_id)

    assert response.status_code == 204
    item = await Item.get(item_id)
    assert not item
    response = await client.get("/auth/logout")
    assert response.status_code == 200

    """
        Visitor deletes post
    """
    custom_item = Item(
        title="Custom item",
        desc="Custom item",
        visibility=Visibility.ALL,
        author=user_visitor.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid.png",
        created_at=datetime.utcnow()
    )

    item = await custom_item.create()
    response = await client.post(
        "/auth/login",
        data={
            "username": user_visitor.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200
    item_id = str(item.id)
    response = await client.delete("/items/"+item_id)

    assert response.status_code == 204
    item = await Item.get(item_id)
    assert not item
    response = await client.get("/auth/logout")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_admin_delete_other_post(test_db, client: AsyncClient):
    """
        Admin deletes post
    """
    custom_item = Item(
        title="Custom item",
        desc="Custom item",
        visibility=Visibility.ALL,
        author=user_visitor.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid.png",
        created_at=datetime.utcnow()
    )
    item = await custom_item.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200
    item_id = str(item.id)
    response = await client.delete("/items/"+item_id)

    assert response.status_code == 204
    item = await Item.get(item_id)
    assert not item
    response = await client.get("/auth/logout")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_user_delete_other_post(test_db, client: AsyncClient):
    """
        User deletes post
    """
    custom_item = Item(
        title="Custom item",
        desc="Custom item",
        visibility=Visibility.ALL,
        author=user_admin.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid.png",
        created_at=datetime.utcnow()
    )
    item = await custom_item.create()

    response = await client.post(
        "/auth/login",
        data={
            "username": user_visitor.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200
    item_id = str(item.id)
    response = await client.delete("/items/"+item_id)

    assert response.status_code == 401
    assert response.json()[
        "detail"] == "Need admin privilege to delete another users post"
    item = await Item.get(item_id)
    assert item
    response = await client.get("/auth/logout")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_user_delete_non_existing_post(test_db, client: AsyncClient):
    """
        User deletes post
    """
    custom_item = Item(
        title="Custom item",
        desc="Custom item",
        visibility=Visibility.ALL,
        author=user_admin.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid.png",
        created_at=datetime.utcnow()
    )
    item = await custom_item.create()
    item_id = str(item.id)
    await item.delete()


    response = await client.post(
        "/auth/login",
        data={
            "username": user_admin.username,
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = await client.delete("/items/"+item_id)
    assert response.status_code == 404
    assert response.json()["detail"] == "Post does not exist anymore"
