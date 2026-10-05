from collections.abc import AsyncIterator

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from twake_space_token_broker.app import create_app
from twake_space_token_broker.settings import Settings

ISSUER = "https://sign-up.example.test/"
PUBLIC_BASE_URL = "https://agent-consent.example.test"
CLIENT_ID = "twake-space-agents"
CLIENT_SECRET = "client-secret-for-tests"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="",
        issuer=ISSUER,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        encryption_key=bytes(range(32)),
        public_base_url=PUBLIC_BASE_URL,
    )


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[AsyncClient]:
    app = create_app(settings)
    async with (
        LifespanManager(app) as manager,
        AsyncClient(transport=ASGITransport(app=manager.app), base_url=PUBLIC_BASE_URL) as client,
    ):
        yield client
