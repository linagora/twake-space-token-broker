from httpx import AsyncClient

from tests.conftest import ALICE, MMAUDET, FakeClock, as_agent_of, consent
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
