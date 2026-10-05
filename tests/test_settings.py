import base64

import pytest
from asgi_lifespan import LifespanManager
from httpx import URL, ASGITransport, AsyncClient

from twake_space_token_broker.app import create_app_from_env

PUBLIC_BASE_URL = "https://agent-consent.dev.example.test"


@pytest.fixture
def environment(monkeypatch: pytest.MonkeyPatch, database_url: str) -> pytest.MonkeyPatch:
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("OIDC_ISSUER", "https://sign-up.dev.example.test/")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "client-secret-for-tests")
    monkeypatch.setenv("ENCRYPTION_KEY", base64.b64encode(bytes(range(32))).decode())
    monkeypatch.setenv("PUBLIC_BASE_URL", f"{PUBLIC_BASE_URL}/")
    return monkeypatch


async def test_the_broker_is_configured_by_its_environment(
    environment: pytest.MonkeyPatch,
) -> None:
    app = create_app_from_env()
    async with (
        LifespanManager(app) as manager,
        AsyncClient(transport=ASGITransport(app=manager.app), base_url=PUBLIC_BASE_URL) as client,
    ):
        response = await client.get("/consent")

    location = URL(response.headers["location"])
    assert (
        str(location.copy_with(query=None)) == "https://sign-up.dev.example.test/oauth2/authorize"
    )
    assert location.params["client_id"] == "twake-space-agents"
    assert location.params["redirect_uri"] == f"{PUBLIC_BASE_URL}/callback"


@pytest.mark.parametrize(
    "key",
    [base64.b64encode(bytes(31)).decode(), "not base64!"],
    ids=["shorter than 32 bytes", "not base64"],
)
def test_a_weak_encryption_key_is_refused(environment: pytest.MonkeyPatch, key: str) -> None:
    environment.setenv("ENCRYPTION_KEY", key)

    with pytest.raises(ValueError, match="ENCRYPTION_KEY"):
        create_app_from_env()
