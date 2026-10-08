from dataclasses import replace
from typing import Literal

import pytest
from httpx import AsyncClient

from tests.conftest import (
    ALICE,
    MMAUDET,
    PUBLIC_BASE_URL,
    FakeClock,
    as_agent_of,
    as_left_by_a_broker_without_consent_dates,
    consent,
    consent_with_drive,
    database_dump,
    running,
)
from tests.fake_cozy_stack import FakeCozyStack
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


@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_a_request_on_the_delegation_that_names_no_owner_is_invalid(
    client: AsyncClient, method: str
) -> None:
    response = await client.request(method, "/delegation")

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


async def test_a_revoked_delegation_gives_its_agent_no_more_tokens(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    await consent(client, lemonldap, MMAUDET)
    await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    revoked = await client.delete("/delegation", headers=as_agent_of(MMAUDET))

    response = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))
    assert revoked.status_code == 204
    assert response.status_code == 401
    assert response.json()["code"] == "delegation_missing"


async def test_a_revoked_delegation_is_missing(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    await consent(client, lemonldap, MMAUDET)

    await client.delete("/delegation", headers=as_agent_of(MMAUDET))

    response = await client.get("/delegation", headers=as_agent_of(MMAUDET))
    assert response.status_code == 404
    assert response.json()["code"] == "delegation_missing"


async def test_revoking_a_delegation_leaves_other_owners_alone(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    await consent(client, lemonldap, MMAUDET)
    await consent(client, lemonldap, ALICE)

    await client.delete("/delegation", headers=as_agent_of(MMAUDET))

    response = await client.get("/forward-auth", headers=as_agent_of(ALICE))
    assert response.status_code == 200


async def test_revoking_a_delegation_removes_the_brokers_client_from_the_drive_instance(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)

    response = await client.delete("/delegation", headers=as_agent_of(MMAUDET))

    assert response.status_code == 204
    assert cozy_stack.clients_on(drive) == []


async def test_a_revoked_delegation_leaves_nothing_in_the_brokers_database(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    drive: str,
    database_url: str,
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)

    await client.delete("/delegation", headers=as_agent_of(MMAUDET))

    assert await database_dump(database_url) == ""


async def test_revoking_a_revoked_delegation_changes_nothing(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    await client.delete("/delegation", headers=as_agent_of(MMAUDET))
    # Nothing is left to remove from the instance
    cozy_stack.outage = "unreachable"

    response = await client.delete("/delegation", headers=as_agent_of(MMAUDET))

    assert response.status_code == 204


async def test_revoking_the_delegation_of_an_owner_who_never_consented_changes_nothing(
    client: AsyncClient,
) -> None:
    response = await client.delete("/delegation", headers=as_agent_of(MMAUDET))

    assert response.status_code == 204


@pytest.mark.parametrize("outage", ["error page", "unreachable"])
async def test_a_revocation_the_drive_instance_does_not_answer_is_a_bad_gateway(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    drive: str,
    outage: Literal["error page", "unreachable"],
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    cozy_stack.outage = outage

    response = await client.delete("/delegation", headers=as_agent_of(MMAUDET))

    assert response.status_code == 502
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:twake:problem:drive_unavailable",
        "title": "Drive unavailable",
        "status": 502,
        "detail": "The owner's Drive instance did not answer: their delegation is revoked, but"
        " the broker stays on the instance until the revocation is tried again.",
        "code": "drive_unavailable",
    }


async def test_a_revocation_the_drive_instance_does_not_answer_still_revokes_the_delegation(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    cozy_stack.outage = "unreachable"

    await client.delete("/delegation", headers=as_agent_of(MMAUDET))

    agent = await client.get(
        "/forward-auth", params={"token": "drive"}, headers=as_agent_of(MMAUDET)
    )
    status = await client.get("/delegation", headers=as_agent_of(MMAUDET))
    assert agent.json()["code"] == "delegation_missing"
    assert status.status_code == 404


async def test_a_revocation_tried_again_once_the_drive_instance_answers_removes_the_broker(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    drive: str,
    database_url: str,
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    cozy_stack.outage = "unreachable"
    await client.delete("/delegation", headers=as_agent_of(MMAUDET))
    cozy_stack.outage = None

    response = await client.delete("/delegation", headers=as_agent_of(MMAUDET))

    assert response.status_code == 204
    assert cozy_stack.clients_on(drive) == []
    assert await database_dump(database_url) == ""


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


async def test_a_delegation_kept_before_revocations_keeps_its_drive_client_for_another_try(
    settings: Settings,
    lemonldap: FakeLemonLDAP,
    clock: FakeClock,
    cozy_stack: FakeCozyStack,
    drive: str,
    database_url: str,
) -> None:
    async with running(settings, lemonldap, clock, cozy_stack) as broker:
        await consent_with_drive(broker, lemonldap, cozy_stack, MMAUDET)
    await as_left_by_a_broker_without_consent_dates(database_url, changed_at="2026-09-01T08:00:00Z")
    cozy_stack.outage = "unreachable"

    async with running(settings, lemonldap, clock, cozy_stack) as broker:
        failed = await broker.delete("/delegation", headers=as_agent_of(MMAUDET))
        cozy_stack.outage = None
        response = await broker.delete("/delegation", headers=as_agent_of(MMAUDET))

    assert failed.status_code == 502
    assert response.status_code == 204
    assert cozy_stack.clients_on(drive) == []
