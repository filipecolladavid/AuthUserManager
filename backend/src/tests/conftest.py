import pytest
from httpx import AsyncClient

from ..main import app


@pytest.fixture(scope='module')
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope='module')
async def client():
    async with AsyncClient(app=app, base_url="http://localhost:8000/api") as client:
        yield client
