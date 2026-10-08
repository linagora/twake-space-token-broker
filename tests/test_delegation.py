from dataclasses import replace

from httpx import AsyncClient

from tests.conftest import (
    ALICE,
    MMAUDET,
    PUBLIC_BASE_URL,
    FakeClock,
    as_agent_of,
    as_left_by_a_broker_without_consent_dates,
    consent,
    running,
)
from tests.fake_lemonldap import ACCESS_TOKEN_LIFETIME, FakeLemonLDAP
from twake_space_token_broker.settings import Settings

MMAUDETS_LINK = f"{PUBLIC_BASE_URL}/consent?owner=mmaudet%40example.test"

DAY = 24 * 3600


async def test_a_delegation_lasts_thirty_days_from_the_consent(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    await consent(client, lemonldap, MMAUDET)

    response = await client.get("/delegation", headers=as_agent_of(MMAUDET))

    assert response.status_code == 200
    assert response.json() == {
        "consented_at": "2026-09-21T14:13:20Z",
        "expires_at": "2026-10-21T14:13:20Z",
        "consent_url": MMAUDETS_LINK,
    }


async def test_a_delegation_lasts_as_long_as_the_broker_is_set_to_keep_it(
    settings: Settings, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    async with running(
        replace(settings, delegation_lifetime_seconds=7 * DAY), lemonldap, clock
    ) as broker:
        await consent(broker, lemonldap, MMAUDET)
        response = await broker.get("/delegation", headers=as_agent_of(MMAUDET))

    assert response.json()["expires_at"] == "2026-09-28T14:13:20Z"


async def test_an_expired_delegation_still_tells_when_it_expired(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    await consent(client, lemonldap, MMAUDET)
    clock.advance(31 * DAY)
    lemonldap.end_offline_session(MMAUDET)
    expired = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    response = await client.get("/delegation", headers=as_agent_of(MMAUDET))

    assert expired.json()["code"] == "delegation_expired"
    assert response.status_code == 200
    assert response.json() == {
        "consented_at": "2026-09-21T14:13:20Z",
        "expires_at": "2026-10-21T14:13:20Z",
        "consent_url": MMAUDETS_LINK,
    }


async def test_an_owner_who_never_consented_has_no_delegation(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    await consent(client, lemonldap, ALICE)

    response = await client.get("/delegation", headers=as_agent_of(MMAUDET))

    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:twake:problem:delegation_missing",
        "title": "Delegation missing",
        "status": 404,
        "detail": "The user has not let their agent act for them yet: they must open the consent"
        " link.",
        "code": "delegation_missing",
        "consent_url": MMAUDETS_LINK,
    }


async def test_a_request_on_the_delegation_that_names_no_owner_is_invalid(
    client: AsyncClient,
) -> None:
    response = await client.get("/delegation")

    assert response.status_code == 400
    assert response.json()["code"] == "missing_user_email"


async def test_a_refresh_keeps_the_consent_date(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    """LemonLDAP 2.21 counts an offline session from the consent, and no refresh extends it."""
    # The broker then stores each new refresh token
    lemonldap.rotates_refresh_tokens = True
    await consent(client, lemonldap, MMAUDET)
    clock.advance(ACCESS_TOKEN_LIFETIME)
    refreshed = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    response = await client.get("/delegation", headers=as_agent_of(MMAUDET))

    assert refreshed.status_code == 200
    assert response.json()["consented_at"] == "2026-09-21T14:13:20Z"


async def test_consenting_again_starts_the_delegation_over(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    await consent(client, lemonldap, MMAUDET)
    clock.advance(10 * DAY)

    await consent(client, lemonldap, MMAUDET)

    response = await client.get("/delegation", headers=as_agent_of(MMAUDET))
    assert response.json()["consented_at"] == "2026-10-01T14:13:20Z"
    assert response.json()["expires_at"] == "2026-10-31T14:13:20Z"


async def test_a_delegation_kept_before_consent_dates_dates_from_its_last_change(
    settings: Settings, lemonldap: FakeLemonLDAP, clock: FakeClock, database_url: str
) -> None:
    """Without rotation, which LemonLDAP does only for a client set to, a refresh changes nothing:
    a delegation last changed when its owner consented."""
    async with running(settings, lemonldap, clock) as broker:
        await consent(broker, lemonldap, MMAUDET)
    await as_left_by_a_broker_without_consent_dates(database_url, changed_at="2026-09-01T08:00:00Z")

    async with running(settings, lemonldap, clock) as broker:
        response = await broker.get("/delegation", headers=as_agent_of(MMAUDET))

    assert response.json()["consented_at"] == "2026-09-01T08:00:00Z"
    assert response.json()["expires_at"] == "2026-10-01T08:00:00Z"
