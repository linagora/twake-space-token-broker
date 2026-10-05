from httpx import URL, AsyncClient, Response

from tests.conftest import (
    CLIENT_ID,
    ISSUER,
    MMAUDET,
    PUBLIC_BASE_URL,
    as_agent_of,
    consent,
    database_dump,
)
from tests.fake_lemonldap import FakeLemonLDAP


def assert_consent_refused(response: Response) -> None:
    """The user sees why, in French, with a link to start over."""
    assert response.status_code == 400
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

    assert_consent_refused(response)
    unknown = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))
    assert unknown.json()["code"] == "delegation_missing"


async def test_a_callback_in_a_browser_that_did_not_start_the_consent_is_refused(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    started = await client.get("/consent")
    callback = lemonldap.sign_in(started.headers["location"], MMAUDET)
    client.cookies.clear()

    response = await client.get(callback)

    assert_consent_refused(response)
