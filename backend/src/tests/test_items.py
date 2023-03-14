from datetime import datetime
import pytest
from httpx import AsyncClient
from motor.motor_asyncio import AsyncIOMotorClient

from src.config.database import startDB
from src.config.settings import settings
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

    global not_verified_user
    global visitor_user
    global creator_user
    global admin_user

    global item_all
    global item_users
    global item_admin

    not_verified_user = User(
        username="not_verified",
        email="not_verified@gmail.com",
        password=hash_password("testpassword"),
        verified=False,
        privileges=Privileges.PENDING,
        created_at=datetime.utcnow()
    )

    visitor_user = User(
        username="visitor",
        email="visitor@gmail.com",
        password=hash_password("testpassword"),
        verified=True,
        privileges=Privileges.VISITOR,
        created_at=datetime.utcnow()
    )

    creator_user = User(
        username="creator",
        email="creator@gmail.com",
        password=hash_password("testpassword"),
        verified=True,
        privileges=Privileges.CREATOR,
        created_at=datetime.utcnow()
    )

    admin_user = User(
        username="admin",
        email="admin@gmail.com",
        password=hash_password("testpassword"),
        verified=True,
        privileges=Privileges.ADMIN,
        created_at=datetime.utcnow()
    )

    await User.insert_many([not_verified_user, visitor_user, creator_user, admin_user])

    item_all = Item(
        title="A post for all",
        desc="A post for all",
        visibility=Visibility.ALL,
        author=admin_user.username,
        pic_url="http:://localhost:9000/post_for_all",
        created_at=datetime.utcnow()
    )

    item_users = Item(
        title="A post for users",
        desc="A post for users",
        visibility=Visibility.USERS,
        author=admin_user.username,
        pic_url="http:://localhost:9000/post_for_users",
        created_at=datetime.utcnow()
    )

    item_admin = Item(
        title="A post for admins",
        desc="A post for admins",
        visibility=Visibility.ADMIN,
        author=admin_user.username,
        pic_url="http:://localhost:9000/post_for_admins",
        created_at=datetime.utcnow()
    )

    await Item.insert_many([item_all, item_users, item_admin])

    response = await client.get("/users/")

    assert response.status_code == 200
    assert len(response.json()) == 4

    response = await client.post(
        "/auth/login",
        data={
            "username": admin_user.username,
            "password": "testpassword"
        }
    )

    assert response.status_code == 200

    response = await client.get("/items/")
    assert response.status_code == 200
    assert len(response.json()) == 3

    response = await client.get("/auth/logout")
    assert response.status_code == 200


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
            "username": not_verified_user.username,
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
            "username": visitor_user.username,
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
            "username": creator_user.username,
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
            "username": admin_user.username,
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


