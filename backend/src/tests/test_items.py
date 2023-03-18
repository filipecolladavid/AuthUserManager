from datetime import datetime
from bson import ObjectId
import pytest
from httpx import AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient

from src.config.database import startDB
from src.config.settings import MinioBaseUrl, settings
from src.config.storage import bucket, minio_client
from src.models.items import Item, Visibility
from src.utils import hash_password, verify_password, delete_minio, get_user_media_list, delete_user_media
from src.tests.test_utils import login, logout
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

    assert user_admin.username == "admin"
    assert user_creator.username == "creator"
    assert user_visitor.username == "visitor"
    assert user_not_verified.username == "not_verified"

"""
    Get items
"""


@pytest.mark.anyio
async def test_get_items_non_users(test_db, client: AsyncClient):
    await item_all.create()
    await item_users.create()
    await item_admin.create()

    db_items = await Item.find(Item.visibility <= Visibility.ALL).to_list()

    response = await client.get("/items/")
    assert response.status_code == 200
    assert len(response.json()) == len(db_items)
    assert not has_visibility_greater_than(response.json(), Visibility.ALL)

    # Not verified user
    await user_not_verified.create()
    await login(user_not_verified.username, "testpassword", client)

    response = await client.get("/items/")
    assert response.status_code == 200
    assert len(response.json()) == len(db_items)
    assert not has_visibility_greater_than(response.json(), Visibility.ALL)

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_get_items_users(test_db, client: AsyncClient):
    await user_visitor.create()

    item_test_admins = Item(
        title="A post for admins by visitor",
        desc="A post for admins by visitor",
        visibility=Visibility.ADMIN,
        author=user_visitor.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid_2.png",
        created_at=datetime.utcnow()
    )

    await item_test_admins.create()

    await login(user_visitor.username, "testpassword", client)

    response = await client.get("/items/")
    db_items = await Item.find({"$or": [{"visibility": {"$lte": Visibility.USERS}},
                                        {"author": user_visitor.username}]}).to_list()
    assert response.status_code == 200
    assert len(response.json()) == len(db_items)
    items = response.json()

    for item in items:
        if item["visibility"] >= Visibility.ADMIN and item["author"] != user_visitor.username:
            assert False

    await logout(client)

    await item_test_admins.delete()
    await User.delete_all()


@pytest.mark.anyio
async def test_get_items_admins(test_db, client: AsyncClient):
    await user_admin.create()
    await login(user_admin.username, "testpassword", client)

    response = await client.get("/items/")
    db_items = await Item.find(Item.visibility <= Visibility.ADMIN).to_list()
    assert response.status_code == 200
    assert len(response.json()) == len(db_items)
    assert not has_visibility_greater_than(response.json(), Visibility.ADMIN)

    await logout(client)

    await User.delete_all()


@pytest.mark.anyio
async def test_user_gets_own_item(test_db, client: AsyncClient):
    # User should always get his post regardless of his privilege
    await user_visitor.create()
    item_test = Item(
        title="A post",
        desc="A post",
        visibility=Visibility.ALL,
        author=user_visitor.username,
        pic_url="http://0.0.0.0:9000/media/admin/invalid_2.png",
        created_at=datetime.utcnow()
    )
    item = await item_test.create()

    await login(user_visitor.username, "testpassword", client)

    response = await client.get("/items/"+str(item.id))
    print(response.json())
    assert response.status_code == 200
    assert response.json()["title"] == "A post"
    assert response.json()["desc"] == "A post"
    assert response.json()["visibility"] == Visibility.ALL

    item.visibility = Visibility.USERS
    await item.save()

    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    assert response.json()["title"] == "A post"
    assert response.json()["desc"] == "A post"
    assert response.json()["visibility"] == Visibility.USERS

    await item.delete()

    item.visibility = Visibility.ADMIN
    await item.save()

    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    assert response.json()["title"] == "A post"
    assert response.json()["desc"] == "A post"
    assert response.json()["visibility"] == Visibility.ADMIN

    await logout(client)
    await Item.delete_all()
    await User.delete_all()


@pytest.mark.anyio
async def test_get_other_user_post(test_db, client: AsyncClient):

    await user_not_verified.create()
    await user_visitor.create()
    await user_creator.create()
    await user_admin.create()

    item_test = Item(
        title="A post",
        desc="A post",
        visibility=Visibility.ALL,
        author="SomeOtherUser",
        pic_url="http://0.0.0.0:9000/media/admin/invalid_2.png",
        created_at=datetime.utcnow()
    )
    """

        Visibility ALL

    """
    item = await item_test.create()

    # Not logged in
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200

    # Not verified
    await login(user_not_verified.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    await logout(client)

    # Visitor
    await login(user_visitor.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    await logout(client)

    # Creator
    await login(user_creator.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    await logout(client)

    # Admin
    await login(user_admin.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    await logout(client)

    """

        Visibility Users

    """
    item.visibility = Visibility.USERS
    await item.save()

    # Not logged in
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authorized to see this post"

    # Not verified
    await login(user_not_verified.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authorized to see this post"
    await logout(client)

    # Visitor
    await login(user_visitor.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    await logout(client)

    # Creator
    await login(user_creator.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    await logout(client)

    # Admin
    await login(user_admin.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    await logout(client)

    """
        Visibility ADMIN
    """
    item.visibility = Visibility.ADMIN
    await item.save()

    # Not logged in
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authorized to see this post"

    # Not verified
    await login(user_not_verified.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authorized to see this post"
    await logout(client)

    # Visitor
    await login(user_visitor.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authorized to see this post"
    await logout(client)

    # Creator
    await login(user_creator.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authorized to see this post"
    await logout(client)

    # Admin
    await login(user_admin.username, "testpassword", client)
    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    await logout(client)

    await Item.delete_all()
    await User.delete_all()


"""
    Create Item
"""


@pytest.mark.anyio
async def test_user_creates_item(test_db, client: AsyncClient):
    await user_creator.create()
    await login(user_creator.username, "testpassword", client)

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
        }
    )

    assert response.status_code == 200
    item_id = response.json()["_id"]

    db_item = await Item.get(item_id)

    assert db_item
    assert response.json()["title"] == "A title for a picture"
    assert response.json()["title"] == db_item.title
    assert response.json()["desc"] == "A desc for a picture"
    assert response.json()["desc"] == db_item.desc
    assert response.json()["visibility"] == Visibility.ALL
    assert response.json()["visibility"] == db_item.visibility
    assert response.json()["author"] == user_creator.username
    assert response.json()["author"] == db_item.author
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_creator.username+"/"+item_id+".jpeg"
    assert response.json()["pic_url"] == db_item.pic_url

    obj = delete_minio(db_item.pic_url)
    assert obj

    await logout(client)
    obj = delete_minio(db_item.pic_url)
    assert not obj

    await user_admin.create()
    await login(user_admin.username, "testpassword", client)

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
        }
    )

    assert response.status_code == 200
    item_id = response.json()["_id"]

    db_item = await Item.get(item_id)

    assert db_item
    assert response.json()["title"] == "A title for a picture"
    assert response.json()["title"] == db_item.title
    assert response.json()["desc"] == "A desc for a picture"
    assert response.json()["desc"] == db_item.desc
    assert response.json()["visibility"] == Visibility.ALL
    assert response.json()["visibility"] == db_item.visibility
    assert response.json()["author"] == user_admin.username
    assert response.json()["author"] == db_item.author
    assert response.json()["pic_url"] == MinioBaseUrl + \
        bucket+"/"+user_admin.username+"/"+item_id+".jpeg"
    assert response.json()["pic_url"] == db_item.pic_url

    obj = delete_minio(db_item.pic_url)
    assert obj

    await logout(client)
    obj = delete_minio(db_item.pic_url)
    assert not obj

    await User.delete_all()
    await Item.delete_all()


@pytest.mark.anyio
async def test_create_item_invalid_parameter(test_db, client: AsyncClient):
    await user_creator.create()
    await login(user_creator.username, "testpassword", client)

    # Invalid visibility

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

    db_items = await Item.find().to_list()

    for i in db_items:
        assert i.visibility != "invalid"

    assert response.status_code == 400
    assert response.json()["detail"] == "Visibility not valid"

    # Invalid file
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

    db_item = await Item.find(Item.title == "A title for a picture").to_list()
    assert len(db_item) == 0

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid type of file"

    await logout(client)
    await User.delete_all()
    await Item.delete_all()


@pytest.mark.anyio
async def test_create_item_unauthorized(test_db, client: AsyncClient):

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    # Not logged in
    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "all"
        }
    )

    db_item = await Item.find(Item.title == "A title for a picture").to_list()
    assert len(db_item) == 0

    assert response.status_code == 401
    assert response.json()["detail"] == "You are not logged in"

    # Not verified
    await user_not_verified.create()

    await login(user_not_verified.username, "testpassword", client)

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "all"
        }
    )

    db_item = await Item.find(Item.title == "A title for a picture").to_list()
    assert len(db_item) == 0

    assert response.status_code == 401
    assert response.json()["detail"] == "Please verify your account"

    await logout(client)

    # Visitor
    await user_visitor.create()

    await login(user_visitor.username, "testpassword", client)

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "A title for a picture",
            "desc": "A desc for a picture",
            "visibility": "all"
        }
    )

    db_item = await Item.find(Item.title == "A title for a picture").to_list()
    assert len(db_item) == 0

    assert response.status_code == 401
    assert response.json()[
        "detail"] == "You need to be a creator to create a post"

    await logout(client)

    await User.delete_all()


"""
    Update item
"""


@pytest.mark.anyio
async def test_update_item_creator(test_db, client: AsyncClient):

    await user_creator.create()
    await login(user_creator.username, "testpassword", client)

    item = await item_users.create()
    item.author = user_creator.username
    await item.save()

    # Update all fields - picture can't be changed (all fields are required)
    response = await client.put(
        "/items/"+str(item.id),
        data={
            "title": "Changed title",
            "desc": "Changed desc",
            "visibility": "users",
        }
    )
    assert response.status_code == 200

    assert response.json()["_id"] == str(item.id)
    assert response.json()["title"] == "Changed title"
    assert response.json()["desc"] == "Changed desc"
    assert response.json()["visibility"] == Visibility.USERS
    assert response.json()["author"] == user_creator.username

    await logout(client)

    delete_user_media(user_creator.username)

    await User.delete_all()
    await Item.delete_all()


@pytest.mark.anyio
async def test_update_item_visitor(test_db, client: AsyncClient):
    await user_visitor.create()
    await login(user_visitor.username, "testpassword", client)

    item = await item_users.create()
    item.author = user_visitor.username
    await item.save()

    # Update all fields - picture can't be changed (all fields are required)
    response = await client.put(
        "/items/"+str(item.id),
        data={
            "title": "Changed title",
            "desc": "Changed desc",
            "visibility": "users",
        }
    )
    assert response.status_code == 200

    assert response.json()["_id"] == str(item.id)
    assert response.json()["title"] == "Changed title"
    assert response.json()["desc"] == "Changed desc"
    assert response.json()["visibility"] == Visibility.USERS
    assert response.json()["author"] == user_visitor.username

    await logout(client)

    delete_user_media(user_visitor.username)

    await User.delete_all()
    await Item.delete_all()


@pytest.mark.anyio
async def test_admin_update_other_user(test_db, client: AsyncClient):
    await user_admin.create()
    await login(user_admin.username, "testpassword", client)

    item = await item_users.create()
    item.author = user_creator.username
    await item.save()

    response = await client.put(
        "/items/"+str(item.id),
        data={
            "title": "Changed title",
            "desc": "Changed desc",
            "visibility": "admin"
        }
    )
    assert response.status_code == 200
    assert response.json()["_id"] == str(item.id)
    assert response.json()["title"] == "Changed title"
    assert response.json()["desc"] == "Changed desc"
    assert response.json()["visibility"] == Visibility.ADMIN

    await logout(client)

    await Item.delete_all()
    await User.delete_all()


@pytest.mark.anyio
async def test_update_invalid_parameter(test_db, client: AsyncClient):
    await user_creator.create()
    await login(user_creator.username, "testpassword", client)

    item = await item_users.create()
    item.author = user_creator.username
    await item.save()

    response = await client.put(
        "/items/"+str(item.id),
        data={
            "title": "Changed title",
            "desc": "Changed desc",
            "visibility": "invalid"
        }
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Visibility not valid"

    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    assert response.json()["title"] == "A post for users"
    assert response.json()["desc"] == "A post for users"
    assert response.json()["visibility"] == Visibility.USERS

    delete_user_media(user_creator.username)

    await logout(client)
    await User.delete_all()
    await Item.delete_all()


@pytest.mark.anyio
async def test_update_unauthorized(test_db, client: AsyncClient):
    await user_creator.create()
    await login(user_creator.username, "testpassword", client)

    item = await item_all.create()
    item.author == user_visitor.username
    await item.save()

    response = await client.put(
        "/items/"+str(item.id),
        data={
            "title": "Changed title",
            "desc": "Changed desc",
            "visibility": "users"
        }
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "You can't change another users post"

    response = await client.get("/items/"+str(item.id))
    assert response.status_code == 200
    assert response.json()["title"] == "A post for all"
    assert response.json()["desc"] == "A post for all"
    assert response.json()["visibility"] == Visibility.ALL

    delete_user_media(user_creator.username)
    delete_user_media(user_visitor.username)

    await logout(client)
    await User.delete_all()
    await Item.delete_all()


@pytest.mark.anyio
async def test_delete_post(test_db, client: AsyncClient):
    # Creator deletes post
    await user_creator.create()
    await login(user_creator.username, "testpassword", client)

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "Picture all",
            "desc": "Picture all",
        }
    )
    assert response.status_code == 200
    item_id = response.json()["_id"]
    pic_url = response.json()["pic_url"]

    response = await client.delete(
        "/items/"+item_id
    )
    assert response.status_code == 204

    item = await Item.get(item_id)
    assert not item
    assert not delete_minio(url=pic_url)

    # Visitor deletes post
    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "Picture all",
            "desc": "Picture all",
        }
    )
    assert response.status_code == 200
    item_id = response.json()["_id"]
    pic_url = response.json()["pic_url"]

    user = await User.find_one(User.username == user_creator.username)
    assert user
    user.privileges = Privileges.VISITOR
    await user.save()

    response = await client.delete(
        "/items/"+item_id
    )
    assert response.status_code == 204

    item = await Item.get(item_id)
    assert not item
    assert not delete_minio(url=pic_url)

    await logout(client)
    await User.delete_all()
    await Item.delete_all()


@pytest.mark.anyio
async def test_admin_delete_other_post(test_db, client: AsyncClient):
    await user_creator.create()
    await user_admin.create()
    await login(user_creator.username, "testpassword", client)

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "Picture all",
            "desc": "Picture all",
        }
    )
    assert response.status_code == 200
    item_id = response.json()["_id"]
    pic_url = response.json()["pic_url"]

    await logout(client)
    await login(user_admin.username, "testpassword", client)

    response = await client.delete(
        "/items/"+item_id
    )
    assert response.status_code == 204

    item = await Item.get(item_id)
    assert not item
    assert not delete_minio(url=pic_url)

    await logout(client)
    await User.delete_all()
    await Item.delete_all()


@pytest.mark.anyio
async def test_user_delete_other_post(test_db, client: AsyncClient):
    await user_creator.create()
    await user_visitor.create()
    await login(user_creator.username, "testpassword", client)

    file = "pizza-cat.jpeg"
    _files = {'img': open(file, 'rb')}

    response = await client.post(
        "/items/",
        files=_files,
        data={
            "title": "Picture all",
            "desc": "Picture all",
        }
    )
    assert response.status_code == 200
    item_id = response.json()["_id"]
    pic_url = response.json()["pic_url"]

    await logout(client)
    await login(user_visitor.username, "testpassword", client)

    response = await client.delete(
        "/items/"+item_id
    )
    assert response.status_code == 401
    assert response.json()[
        "detail"] == "Need admin privilege to delete another users post"

    item = await Item.get(item_id)
    assert item
    assert delete_minio(url=pic_url)

    await logout(client)
    await User.delete_all()
    await Item.delete_all()


@pytest.mark.anyio
async def test_user_delete_non_existing_post(test_db, client: AsyncClient):
    await user_admin.create()
    item = await item_all.create()
    item_id = str(item.id)
    await item.delete()
    await login(user_admin.username, "testpassword", client)

    response = await client.delete(
        "/items/"+item_id
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Post not found"

    item = await Item.get(item_id)
    assert not item
