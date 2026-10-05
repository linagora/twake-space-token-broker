import pytest
from httpx import AsyncClient

from tests.conftest import ALICE, MMAUDET, PUBLIC_BASE_URL, FakeClock, as_agent_of, consent
from tests.fake_lemonldap import ACCESS_TOKEN_LIFETIME, FakeLemonLDAP


def bearer(authorization: str) -> str:
    scheme, _, token = authorization.partition(" ")
    assert scheme == "Bearer"
    return token


async def test_an_agent_gets_an_access_token_of_its_owner_only(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    await consent(client, lemonldap, MMAUDET)
    await consent(client, lemonldap, ALICE)

    response = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 200
    assert lemonldap.owner_of(bearer(response.headers["authorization"])) == MMAUDET


async def test_an_access_token_is_reused_until_five_minutes_before_it_expires(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    await consent(client, lemonldap, MMAUDET)
    first = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    clock.advance(ACCESS_TOKEN_LIFETIME - 300 - 1)
    second = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert second.headers["authorization"] == first.headers["authorization"]


async def test_an_access_token_is_refreshed_five_minutes_before_it_expires(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    await consent(client, lemonldap, MMAUDET)
    first = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    clock.advance(ACCESS_TOKEN_LIFETIME - 300)
    second = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    refreshed = bearer(second.headers["authorization"])
    assert refreshed != bearer(first.headers["authorization"])
    assert lemonldap.owner_of(refreshed) == MMAUDET


async def test_an_expired_delegation_is_refused_with_the_consent_link(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    await consent(client, lemonldap, MMAUDET)
    lemonldap.end_offline_session(MMAUDET)

    response = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:twake:problem:delegation_expired",
        "title": "Delegation expired",
        "status": 401,
        "detail": "The user's consent to their agent has expired: they must open the consent link"
        " again.",
        "code": "delegation_expired",
        "consent_url": f"{PUBLIC_BASE_URL}/consent",
    }


async def test_an_owner_who_never_consented_is_refused_with_the_consent_link(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    await consent(client, lemonldap, MMAUDET)

    response = await client.get("/forward-auth", headers=as_agent_of(ALICE))

    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:twake:problem:delegation_missing",
        "title": "Delegation missing",
        "status": 401,
        "detail": "The user has not let their agent act for them yet: they must open the consent"
        " link.",
        "code": "delegation_missing",
        "consent_url": f"{PUBLIC_BASE_URL}/consent",
    }


@pytest.mark.parametrize("headers", [{}, {"X-Twake-User-Email": ""}], ids=["missing", "empty"])
async def test_a_request_that_names_no_owner_is_invalid(
    client: AsyncClient, headers: dict[str, str]
) -> None:
    response = await client.get("/forward-auth", headers=headers)

    assert response.status_code == 400
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:twake:problem:missing_user_email",
        "title": "Missing user email",
        "status": 400,
        "detail": "The X-Twake-User-Email header must name the agent's owner.",
        "code": "missing_user_email",
    }
