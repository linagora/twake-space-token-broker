import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Literal

import pytest
from httpx import AsyncClient

from tests.conftest import (
    ALICE,
    MMAUDET,
    MMAUDET_DRIVE,
    PUBLIC_BASE_URL,
    FakeClock,
    as_agent_of,
    consent,
    consent_with_drive,
    database_dump,
    running,
)
from tests.fake_cozy_stack import FakeCozyStack
from tests.fake_lemonldap import ACCESS_TOKEN_LIFETIME, FakeLemonLDAP
from twake_space_token_broker.settings import Settings

DRIVE = {"token": "drive"}
"""The query of the forward-auth of a Drive route."""

FILES = "io.cozy.files:GET,POST"


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


async def test_an_access_token_is_reused_for_a_minute(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    await consent(client, lemonldap, MMAUDET)
    first = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    clock.advance(59)
    second = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert second.headers["authorization"] == first.headers["authorization"]


async def test_a_revoked_delegation_is_refused_after_a_minute(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    """LemonLDAP's access tokens last 10 hours: the broker must ask LemonLDAP again sooner."""
    await consent(client, lemonldap, MMAUDET)
    await client.get("/forward-auth", headers=as_agent_of(MMAUDET))
    lemonldap.end_offline_session(MMAUDET)

    clock.advance(60)
    response = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 401
    assert response.json()["code"] == "delegation_expired"


async def test_token_reuse_counts_from_when_the_broker_asked_lemonldap(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    """A slow answer must not stretch how long a revoked delegation still gets tokens."""
    await consent(client, lemonldap, MMAUDET)
    clock.advance(60)
    lemonldap.latency = 10
    first = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    clock.advance(50)
    second = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert second.headers["authorization"] != first.headers["authorization"]


async def test_an_access_token_is_reused_until_five_minutes_before_it_expires(
    settings: Settings, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    reused_for_its_whole_life = replace(settings, token_reuse_seconds=ACCESS_TOKEN_LIFETIME)
    async with running(reused_for_its_whole_life, lemonldap, clock) as broker:
        await consent(broker, lemonldap, MMAUDET)
        first = await broker.get("/forward-auth", headers=as_agent_of(MMAUDET))

        clock.advance(ACCESS_TOKEN_LIFETIME - 300 - 1)
        second = await broker.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert second.headers["authorization"] == first.headers["authorization"]


async def test_an_access_token_is_refreshed_five_minutes_before_it_expires(
    settings: Settings, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    reused_for_its_whole_life = replace(settings, token_reuse_seconds=ACCESS_TOKEN_LIFETIME)
    async with running(reused_for_its_whole_life, lemonldap, clock) as broker:
        await consent(broker, lemonldap, MMAUDET)
        first = await broker.get("/forward-auth", headers=as_agent_of(MMAUDET))

        clock.advance(ACCESS_TOKEN_LIFETIME - 300)
        second = await broker.get("/forward-auth", headers=as_agent_of(MMAUDET))

    refreshed = bearer(second.headers["authorization"])
    assert refreshed != bearer(first.headers["authorization"])
    assert lemonldap.owner_of(refreshed) == MMAUDET


@pytest.mark.parametrize(
    "revoke",
    [FakeLemonLDAP.end_offline_session, FakeLemonLDAP.delete_from_ldap],
    ids=["offline session ended", "user deleted from LDAP"],
)
async def test_an_expired_delegation_is_refused_with_the_consent_link(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    clock: FakeClock,
    revoke: Callable[[FakeLemonLDAP, str], None],
) -> None:
    await consent(client, lemonldap, MMAUDET)
    clock.advance(30 * 24 * 3600)
    revoke(lemonldap, MMAUDET)

    response = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:twake:problem:delegation_expired",
        "title": "Delegation expired",
        "status": 401,
        "detail": "The user's consent to their agent is no longer valid: they must open the"
        " consent link again.",
        "code": "delegation_expired",
        "consent_url": f"{PUBLIC_BASE_URL}/consent",
    }


async def test_a_refused_delegation_is_logged_with_lemonldaps_error(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    clock: FakeClock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await consent(client, lemonldap, MMAUDET)
    clock.advance(ACCESS_TOKEN_LIFETIME)
    lemonldap.end_offline_session(MMAUDET)

    await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert (
        "twake_space_token_broker.tokens",
        logging.WARNING,
        f"LemonLDAP refused the delegation of {MMAUDET} (invalid_request)",
    ) in caplog.record_tuples


async def test_a_delegation_lemonldap_refuses_stays_stored(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock, database_url: str
) -> None:
    await consent(client, lemonldap, MMAUDET)
    clock.advance(ACCESS_TOKEN_LIFETIME)
    lemonldap.end_offline_session(MMAUDET)
    before = await database_dump(database_url)

    await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    after = await database_dump(database_url)
    assert MMAUDET in after
    assert after == before


async def test_a_revoked_delegation_keeps_answering_delegation_expired(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    await consent(client, lemonldap, MMAUDET)
    clock.advance(ACCESS_TOKEN_LIFETIME)
    lemonldap.end_offline_session(MMAUDET)
    await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    response = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 401
    assert response.json()["code"] == "delegation_expired"


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


async def test_consenting_again_replaces_the_delegation(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    await consent(client, lemonldap, MMAUDET)
    before = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))
    lemonldap.end_offline_session(MMAUDET)

    await consent(client, lemonldap, MMAUDET)

    after = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))
    assert after.status_code == 200
    renewed = bearer(after.headers["authorization"])
    assert renewed != bearer(before.headers["authorization"])
    assert lemonldap.owner_of(renewed) == MMAUDET


async def test_a_refresh_token_lemonldap_rotates_serves_the_next_refresh(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    lemonldap.rotates_refresh_tokens = True
    await consent(client, lemonldap, MMAUDET)
    clock.advance(ACCESS_TOKEN_LIFETIME)
    await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    clock.advance(ACCESS_TOKEN_LIFETIME)
    response = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 200
    assert lemonldap.owner_of(bearer(response.headers["authorization"])) == MMAUDET


async def test_simultaneous_calls_of_an_agent_share_one_refresh(
    client: AsyncClient, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    lemonldap.rotates_refresh_tokens = True
    await consent(client, lemonldap, MMAUDET)
    clock.advance(ACCESS_TOKEN_LIFETIME)

    responses = await asyncio.gather(
        *(client.get("/forward-auth", headers=as_agent_of(MMAUDET)) for _ in range(3))
    )

    assert [response.status_code for response in responses] == [200, 200, 200]
    assert len({response.headers["authorization"] for response in responses}) == 1


@pytest.mark.parametrize("outage", ["error page", "unreachable"])
async def test_lemonldap_failing_to_refresh_is_a_bad_gateway(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    clock: FakeClock,
    outage: Literal["error page", "unreachable"],
) -> None:
    await consent(client, lemonldap, MMAUDET)
    clock.advance(ACCESS_TOKEN_LIFETIME)
    lemonldap.outage = outage

    response = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 502
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:twake:problem:lemonldap_unavailable",
        "title": "LemonLDAP unavailable",
        "status": 502,
        "detail": "LemonLDAP did not answer the token request: try again later.",
        "code": "lemonldap_unavailable",
    }


@pytest.mark.parametrize("outage", ["LDAP down", "session store down"])
async def test_a_delegation_outlives_lemonldap_refusing_it_during_an_outage(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    clock: FakeClock,
    outage: Literal["LDAP down", "session store down"],
) -> None:
    await consent(client, lemonldap, MMAUDET)
    clock.advance(ACCESS_TOKEN_LIFETIME)
    lemonldap.outage = outage
    refused = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    lemonldap.outage = None
    response = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert refused.json()["code"] == "delegation_expired"
    assert response.status_code == 200
    assert lemonldap.owner_of(bearer(response.headers["authorization"])) == MMAUDET


async def test_lemonldap_refusing_the_broker_itself_is_a_bad_gateway(
    settings: Settings, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    """A client secret LemonLDAP no longer accepts says nothing of the user's delegation."""
    async with running(settings, lemonldap, clock) as broker:
        await consent(broker, lemonldap, MMAUDET)
    clock.advance(ACCESS_TOKEN_LIFETIME)
    with_a_wrong_secret = replace(settings, client_secret=settings.client_secret + "-wrong")

    async with running(with_a_wrong_secret, lemonldap, clock) as broker:
        response = await broker.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 502
    assert response.json()["code"] == "lemonldap_unavailable"


async def test_a_delegation_outlives_a_restart_of_the_broker(
    settings: Settings, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    async with running(settings, lemonldap, clock) as broker:
        await consent(broker, lemonldap, MMAUDET)

    async with running(settings, lemonldap, clock) as broker:
        response = await broker.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 200
    assert lemonldap.owner_of(bearer(response.headers["authorization"])) == MMAUDET


async def test_a_delegation_kept_under_another_encryption_key_counts_as_expired(
    settings: Settings, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> None:
    async with running(settings, lemonldap, clock) as broker:
        await consent(broker, lemonldap, MMAUDET)

    with_another_key = replace(settings, encryption_key=bytes(32))
    async with running(with_another_key, lemonldap, clock) as broker:
        response = await broker.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 401
    assert response.json()["code"] == "delegation_expired"


async def test_a_drive_route_gets_the_owners_drive_token_and_instance(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)

    response = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    assert response.status_code == 200
    # LemonLDAP's token still names the user to the contract
    assert lemonldap.owner_of(bearer(response.headers["authorization"])) == MMAUDET
    assert cozy_stack.access_of(response.headers["x-twake-drive-token"]) == (drive, FILES)
    assert response.headers["x-twake-drive-instance"] == drive


async def test_a_route_that_does_not_ask_for_drive_gets_no_drive_token(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)

    response = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))

    assert response.status_code == 200
    assert "x-twake-drive-token" not in response.headers
    assert "x-twake-drive-instance" not in response.headers


async def stop_on_drive(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack
) -> None:
    """The owner reaches their Drive instance, where they never accept."""
    cozy_stack.create_instance(MMAUDET_DRIVE)
    lemonldap.workplaces[MMAUDET] = MMAUDET_DRIVE
    assert (await consent(client, lemonldap, MMAUDET)).status_code == 302


async def have_no_drive_instance(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack
) -> None:
    assert (await consent(client, lemonldap, MMAUDET)).status_code == 200


ConsentWithoutDrive = Callable[[AsyncClient, FakeLemonLDAP, FakeCozyStack], Awaitable[None]]


@pytest.mark.parametrize("consent_without_drive", [have_no_drive_instance, stop_on_drive])
async def test_a_drive_route_without_a_drive_delegation_is_refused_with_the_consent_link(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    consent_without_drive: ConsentWithoutDrive,
) -> None:
    await consent_without_drive(client, lemonldap, cozy_stack)

    response = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

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


async def test_a_drive_access_token_is_reused_for_a_minute(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    clock: FakeClock,
    drive: str,
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    first = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    clock.advance(59)
    second = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    assert second.headers["x-twake-drive-token"] == first.headers["x-twake-drive-token"]


async def test_a_drive_access_token_is_refreshed_after_a_minute(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    clock: FakeClock,
    drive: str,
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    first = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    clock.advance(60)
    second = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    refreshed = second.headers["x-twake-drive-token"]
    assert refreshed != first.headers["x-twake-drive-token"]
    assert cozy_stack.access_of(refreshed) == (drive, FILES)


async def test_a_drive_delegation_the_owner_removed_from_their_instance_is_refused(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    clock: FakeClock,
    drive: str,
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    cozy_stack.remove_clients(drive)

    clock.advance(60)
    response = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    assert response.status_code == 401
    assert response.json()["code"] == "delegation_expired"
    assert response.json()["consent_url"] == f"{PUBLIC_BASE_URL}/consent"


async def test_a_drive_route_of_an_owner_whose_lemonldap_delegation_ended_is_refused(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    clock: FakeClock,
    drive: str,
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    lemonldap.end_offline_session(MMAUDET)

    clock.advance(60)
    response = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    assert response.status_code == 401
    assert response.json()["code"] == "delegation_expired"


@pytest.mark.parametrize("outage", ["error page", "unreachable"])
async def test_a_drive_instance_failing_to_refresh_is_a_bad_gateway(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    clock: FakeClock,
    drive: str,
    outage: Literal["error page", "unreachable"],
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    clock.advance(60)
    cozy_stack.outage = outage

    response = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    assert response.status_code == 502
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:twake:problem:drive_unavailable",
        "title": "Drive unavailable",
        "status": 502,
        "detail": "The owner's Drive instance did not answer the token request: try again later.",
        "code": "drive_unavailable",
    }


async def test_a_refresh_token_the_drive_instance_rotates_serves_the_next_refresh(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    clock: FakeClock,
    drive: str,
) -> None:
    cozy_stack.rotates_refresh_tokens = True
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    clock.advance(60)
    await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    clock.advance(60)
    response = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    assert response.status_code == 200
    assert cozy_stack.access_of(response.headers["x-twake-drive-token"]) == (drive, FILES)


async def test_simultaneous_drive_calls_of_an_agent_share_one_refresh(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    clock: FakeClock,
    drive: str,
) -> None:
    cozy_stack.rotates_refresh_tokens = True
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    clock.advance(60)

    responses = await asyncio.gather(
        *(client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET)) for _ in range(3))
    )

    assert [response.status_code for response in responses] == [200, 200, 200]
    assert len({response.headers["x-twake-drive-token"] for response in responses}) == 1


async def test_a_token_the_broker_does_not_give_is_an_invalid_request(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    """A mistyped query of a route must not leave its contract without the token it needs."""
    await consent(client, lemonldap, MMAUDET)

    response = await client.get(
        "/forward-auth", params={"token": "drvie"}, headers=as_agent_of(MMAUDET)
    )

    assert response.status_code == 400
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:twake:problem:unknown_token",
        "title": "Unknown token",
        "status": 400,
        "detail": "The token query parameter can only ask for drive.",
        "code": "unknown_token",
    }


async def test_consenting_again_without_a_drive_instance_drops_the_drive_delegation(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    del lemonldap.workplaces[MMAUDET]

    await consent(client, lemonldap, MMAUDET)

    response = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))
    assert response.json()["code"] == "delegation_missing"
    assert cozy_stack.clients_on(drive) == []


async def test_consenting_again_leaves_one_client_of_the_broker_on_the_drive_instance(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)

    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)

    assert len(cozy_stack.clients_on(drive)) == 1
    response = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))
    assert cozy_stack.access_of(response.headers["x-twake-drive-token"]) == (drive, FILES)


async def test_consenting_again_while_the_drive_instance_is_unreachable_drops_drive(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    """A new consent replaces the whole delegation, even when the instance cannot be told."""
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)
    cozy_stack.outage = "unreachable"

    await consent(client, lemonldap, MMAUDET)

    response = await client.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))
    assert response.json()["code"] == "delegation_missing"


async def test_consenting_again_under_another_encryption_key_replaces_the_drive_delegation(
    settings: Settings,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    clock: FakeClock,
    drive: str,
) -> None:
    async with running(settings, lemonldap, clock, cozy_stack) as broker:
        await consent_with_drive(broker, lemonldap, cozy_stack, MMAUDET)

    with_another_key = replace(settings, encryption_key=bytes(32))
    async with running(with_another_key, lemonldap, clock, cozy_stack) as broker:
        await consent_with_drive(broker, lemonldap, cozy_stack, MMAUDET)
        response = await broker.get("/forward-auth", params=DRIVE, headers=as_agent_of(MMAUDET))

    assert cozy_stack.access_of(response.headers["x-twake-drive-token"]) == (drive, FILES)
