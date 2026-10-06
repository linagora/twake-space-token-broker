from collections.abc import Callable

import pytest
from httpx import URL, AsyncClient, Response

from tests.conftest import (
    CLIENT_ID,
    ISSUER,
    MMAUDET,
    PUBLIC_BASE_URL,
    FakeClock,
    as_agent_of,
    consent,
    consent_with_drive,
    database_dump,
)
from tests.fake_cozy_stack import FakeCozyStack
from tests.fake_lemonldap import FakeLemonLDAP


def assert_consent_failed(response: Response, status_code: int = 400) -> None:
    """The user sees why, in French, with a link to start over."""
    assert response.status_code == status_code
    assert response.headers["content-type"].startswith("text/html")
    assert 'href="/consent"' in response.text


async def test_consent_sends_the_user_to_lemonldap_with_pkce(client: AsyncClient) -> None:
    response = await client.get("/consent")

    assert response.status_code == 302
    location = URL(response.headers["location"])
    assert str(location.copy_with(query=None)) == f"{ISSUER}oauth2/authorize"
    assert location.params["response_type"] == "code"
    assert location.params["client_id"] == CLIENT_ID
    assert location.params["redirect_uri"] == f"{PUBLIC_BASE_URL}/callback"
    assert location.params["scope"] == "openid email offline_access"
    assert location.params["code_challenge_method"] == "S256"
    assert len(location.params["code_challenge"]) == 43
    assert location.params["state"]
    cookie = response.headers["set-cookie"].lower()
    assert all(
        attribute in cookie for attribute in ("httponly", "secure", "samesite=lax", "max-age=600")
    )


async def test_consent_asks_lemonldap_for_a_fresh_login(client: AsyncClient) -> None:
    """A browser still signed in as someone else must not consent for them without a word."""
    response = await client.get("/consent")

    assert URL(response.headers["location"]).params.get("prompt") == "login"


async def test_consent_stores_the_users_refresh_token_encrypted(
    client: AsyncClient, lemonldap: FakeLemonLDAP, database_url: str
) -> None:
    response = await consent(client, lemonldap, MMAUDET)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert MMAUDET in response.text
    stored = await database_dump(database_url)
    assert MMAUDET in stored
    refresh_token = lemonldap.refresh_token_of(MMAUDET)
    assert refresh_token not in stored
    assert refresh_token.encode().hex() not in stored


async def test_a_callback_whose_state_differs_from_the_consent_in_progress_is_refused(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    started = await client.get("/consent")
    callback = URL(lemonldap.sign_in(started.headers["location"], MMAUDET))

    response = await client.get(callback.copy_set_param("state", "forged"))

    assert_consent_failed(response)
    unknown = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))
    assert unknown.json()["code"] == "delegation_missing"


async def test_a_callback_in_a_browser_that_did_not_start_the_consent_is_refused(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    started = await client.get("/consent")
    callback = lemonldap.sign_in(started.headers["location"], MMAUDET)
    client.cookies.clear()

    response = await client.get(callback)

    assert_consent_failed(response)


async def test_a_consent_left_for_more_than_ten_minutes_is_refused(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    started = await client.get("/consent")
    callback = lemonldap.sign_in(started.headers["location"], MMAUDET)
    clock.advance(601)

    response = await client.get(callback)

    assert_consent_failed(response)


async def test_a_sign_in_lemonldap_turned_down_is_refused(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    started = await client.get("/consent")
    callback = URL(lemonldap.sign_in(started.headers["location"], MMAUDET))

    response = await client.get(
        callback.copy_remove_param("code").copy_set_param("error", "access_denied")
    )

    assert_consent_failed(response)


async def test_a_code_lemonldap_refuses_is_refused(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    started = await client.get("/consent")
    callback = URL(lemonldap.sign_in(started.headers["location"], MMAUDET))

    response = await client.get(callback.copy_set_param("code", "code-unknown"))

    assert_consent_failed(response)


async def test_a_consent_lemonldap_cannot_complete_is_a_bad_gateway(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    started = await client.get("/consent")
    callback = lemonldap.sign_in(started.headers["location"], MMAUDET)
    lemonldap.outage = "unreachable"

    response = await client.get(callback)

    assert_consent_failed(response, status_code=502)


async def test_a_consent_without_offline_access_is_a_bad_gateway(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    lemonldap.grants_offline_access = False

    response = await consent(client, lemonldap, MMAUDET)

    assert_consent_failed(response, status_code=502)


async def test_consent_goes_on_to_the_owners_drive_instance_for_reading_and_creating_files(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    response = await consent(client, lemonldap, MMAUDET)

    assert response.status_code == 302
    location = URL(response.headers["location"])
    assert str(location.copy_with(query=None)) == f"https://{drive}/auth/authorize"
    assert location.params["scope"] == "io.cozy.files:GET,POST"
    assert location.params["redirect_uri"] == f"{PUBLIC_BASE_URL}/callback"
    assert len(location.params["code_challenge"]) == 43
    [registered] = cozy_stack.clients_on(drive)
    assert registered["redirect_uris"] == [f"{PUBLIC_BASE_URL}/callback"]
    assert registered["client_name"] == "Assistant Twake Space"
    # Listed among the applications connected to the instance, where the owner can remove it
    assert registered["client_kind"] == "web"


async def test_the_owner_authorizes_drive_through_the_same_consent(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    response = await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert MMAUDET in response.text
    assert "y compris dans Drive" in response.text
    assert 'href="/consent"' not in response.text


async def test_consent_stores_the_drive_delegation_encrypted(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    drive: str,
    database_url: str,
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)

    stored = await database_dump(database_url)
    credentials = cozy_stack.credentials_on(drive)
    assert len(credentials) == 3
    for credential in credentials:
        assert credential not in stored
        assert credential.encode().hex() not in stored


async def test_a_consent_without_a_drive_instance_completes_for_lemonldap_alone(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    response = await consent(client, lemonldap, MMAUDET)

    assert response.status_code == 200
    assert MMAUDET in response.text
    assert "Drive n&#x27;est pas disponible" in response.text
    authorized = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))
    assert authorized.status_code == 200


def userinfo_failing(lemonldap: FakeLemonLDAP) -> None:
    lemonldap.userinfo_outage = True


def not_a_host_name(lemonldap: FakeLemonLDAP) -> None:
    lemonldap.workplaces[MMAUDET] = f"https://{lemonldap.workplaces[MMAUDET]}/"


@pytest.mark.parametrize("fail", [userinfo_failing, not_a_host_name])
async def test_a_drive_instance_lemonldap_cannot_name_leaves_drive_out_of_the_consent(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    drive: str,
    fail: Callable[[FakeLemonLDAP], None],
) -> None:
    """The consent never fails for Drive: an agent may need LemonLDAP's token alone."""
    fail(lemonldap)

    response = await consent(client, lemonldap, MMAUDET)

    assert response.status_code == 200
    assert "Drive n&#x27;est pas disponible" in response.text
    assert cozy_stack.clients_on(drive) == []
