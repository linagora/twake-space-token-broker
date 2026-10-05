from httpx import URL, AsyncClient

from tests.conftest import CLIENT_ID, ISSUER, PUBLIC_BASE_URL


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
