import base64
import os

import pytest
from asgi_lifespan import LifespanManager
from httpx import URL, ASGITransport, AsyncClient

from twake_space_token_broker.app import create_app_from_env
from twake_space_token_broker.settings import Settings

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


def test_token_reuse_lasts_a_minute_by_default(environment: pytest.MonkeyPatch) -> None:
    assert Settings.from_env(os.environ).token_reuse_seconds == 60


def test_the_environment_sets_how_long_an_access_token_is_reused(
    environment: pytest.MonkeyPatch,
) -> None:
    environment.setenv("TOKEN_REUSE_SECONDS", "300")

    assert Settings.from_env(os.environ).token_reuse_seconds == 300


@pytest.mark.parametrize("seconds", ["1m", "-1"], ids=["not a number", "negative"])
def test_a_token_reuse_that_is_not_a_whole_number_of_seconds_is_refused(
    environment: pytest.MonkeyPatch, seconds: str
) -> None:
    environment.setenv("TOKEN_REUSE_SECONDS", seconds)

    with pytest.raises(ValueError, match="TOKEN_REUSE_SECONDS"):
        create_app_from_env()


def test_a_delegation_lasts_thirty_days_by_default(environment: pytest.MonkeyPatch) -> None:
    """As LemonLDAP's offline sessions do by default, which Twake's keep for its agents."""
    assert Settings.from_env(os.environ).delegation_lifetime_seconds == 2_592_000


def test_the_environment_sets_how_long_a_delegation_lasts(
    environment: pytest.MonkeyPatch,
) -> None:
    environment.setenv("DELEGATION_LIFETIME_SECONDS", "604800")

    assert Settings.from_env(os.environ).delegation_lifetime_seconds == 604_800


@pytest.mark.parametrize("seconds", ["30d", "-1"], ids=["not a number", "negative"])
def test_a_delegation_lifetime_that_is_not_a_whole_number_of_seconds_is_refused(
    environment: pytest.MonkeyPatch, seconds: str
) -> None:
    environment.setenv("DELEGATION_LIFETIME_SECONDS", seconds)

    with pytest.raises(ValueError, match="DELEGATION_LIFETIME_SECONDS"):
        create_app_from_env()


def test_drive_is_off_by_default(environment: pytest.MonkeyPatch) -> None:
    assert Settings.from_env(os.environ).drive_instance_domain is None


def test_the_environment_sets_the_domain_of_the_drive_instances(
    environment: pytest.MonkeyPatch,
) -> None:
    environment.setenv("DRIVE_INSTANCE_DOMAIN", "Twake.Example.Test")

    assert Settings.from_env(os.environ).drive_instance_domain == "twake.example.test"


@pytest.mark.parametrize(
    "domain",
    ["https://twake.example.test", "twake", "*.twake.example.test"],
    ids=["a URL", "a single label", "a wildcard"],
)
def test_a_drive_instance_domain_that_is_no_domain_name_is_refused(
    environment: pytest.MonkeyPatch, domain: str
) -> None:
    environment.setenv("DRIVE_INSTANCE_DOMAIN", domain)

    with pytest.raises(ValueError, match="DRIVE_INSTANCE_DOMAIN"):
        create_app_from_env()


def test_twake_space_is_off_by_default(environment: pytest.MonkeyPatch) -> None:
    settings = Settings.from_env(os.environ)

    assert (settings.space_url, settings.space_web_url) == (None, None)


def test_the_environment_sets_where_the_broker_and_the_users_reach_twake_space(
    environment: pytest.MonkeyPatch,
) -> None:
    environment.setenv("SPACE_URL", "http://twake-space-backend.twake-space.svc.cluster.local/")
    environment.setenv("SPACE_WEB_URL", "https://space.dev.example.test/")

    settings = Settings.from_env(os.environ)

    assert settings.space_url == "http://twake-space-backend.twake-space.svc.cluster.local"
    assert settings.space_web_url == "https://space.dev.example.test"


def test_twake_space_without_where_its_users_open_it_is_refused(
    environment: pytest.MonkeyPatch,
) -> None:
    """The Space step would have no page of API tokens to link to."""
    environment.setenv("SPACE_URL", "http://twake-space-backend.twake-space.svc.cluster.local")

    with pytest.raises(ValueError, match="SPACE_WEB_URL"):
        create_app_from_env()
