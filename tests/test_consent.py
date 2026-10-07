from dataclasses import replace
from typing import Literal

import pytest
from httpx import URL, AsyncClient, Response

from tests.conftest import (
    ALICE,
    CLIENT_ID,
    DRIVE_INSTANCE_DOMAIN,
    ISSUER,
    MMAUDET,
    MMAUDET_DRIVE,
    PUBLIC_BASE_URL,
    FakeClock,
    as_agent_of,
    consent,
    consent_with_drive,
    database_dump,
    remove_delegation,
    running,
)
from tests.fake_cozy_stack import FakeCozyStack
from tests.fake_lemonldap import FakeLemonLDAP
from twake_space_token_broker.settings import Settings


def assert_consent_failed(response: Response, status_code: int = 400) -> None:
    """The user sees why, in French, with a link to start over."""
    assert response.status_code == status_code
    assert response.headers["content-type"].startswith("text/html")
    assert 'href="/consent"' in response.text


def assert_authorized_without_drive(response: Response, status_code: int) -> None:
    """The user learns that their agent may act for them, though not in Drive, and may retry."""
    assert response.status_code == status_code
    assert response.headers["content-type"].startswith("text/html")
    assert "sauf dans Drive" in response.text
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
    """The plain link names nobody, so a browser signed in as someone else must sign in again.

    LemonLDAP's "stay connected" defeats it, since that login counts as a fresh one: owners get
    their own link instead.
    """
    response = await client.get("/consent")

    assert URL(response.headers["location"]).params.get("prompt") == "login"


async def test_a_consent_link_for_its_owner_asks_for_no_fresh_login(client: AsyncClient) -> None:
    """A fresh login proves nothing once LemonLDAP keeps a browser signed in ("stay connected"):
    the callback checks who signed in instead, so an owner already signed in consents at once."""
    response = await client.get("/consent", params={"owner": MMAUDET})

    location = URL(response.headers["location"])
    assert "prompt" not in location.params
    assert location.params["login_hint"] == MMAUDET


async def test_a_consent_link_signed_in_as_someone_else_stores_nothing(
    client: AsyncClient, lemonldap: FakeLemonLDAP, database_url: str
) -> None:
    """The browser is still signed in as another account, as LemonLDAP's "stay connected" does."""
    started = await client.get("/consent", params={"owner": MMAUDET})

    response = await client.get(lemonldap.sign_in(started.headers["location"], ALICE))

    assert response.status_code == 403
    assert response.headers["content-type"].startswith("text/html")
    assert MMAUDET in response.text
    assert ALICE in response.text
    assert await database_dump(database_url) == ""


async def test_a_consent_link_signed_in_as_someone_else_leaves_their_delegations_alone(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    database_url: str,
) -> None:
    alice_drive = f"alice.{DRIVE_INSTANCE_DOMAIN}"
    cozy_stack.create_instance(alice_drive)
    lemonldap.workplaces[ALICE] = alice_drive
    await consent_with_drive(client, lemonldap, cozy_stack, ALICE)
    before = await database_dump(database_url)
    client.cookies.clear()
    started = await client.get("/consent", params={"owner": MMAUDET})

    await client.get(lemonldap.sign_in(started.headers["location"], ALICE))

    assert await database_dump(database_url) == before


async def test_an_owner_already_signed_in_consents_through_their_link_drive_included(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    started = await client.get("/consent", params={"owner": MMAUDET})
    to_drive = await client.get(lemonldap.sign_in(started.headers["location"], MMAUDET))

    response = await client.get(cozy_stack.authorize(to_drive.headers["location"]))

    assert response.status_code == 200
    assert "Votre assistant est autorisé" in response.text
    agent = await client.get(
        "/forward-auth", params={"token": "drive"}, headers=as_agent_of(MMAUDET)
    )
    assert agent.status_code == 200


async def test_a_consent_link_is_bound_to_its_owner_exactly(
    client: AsyncClient, lemonldap: FakeLemonLDAP, database_url: str
) -> None:
    """The broker keys a delegation by the email exactly as LemonLDAP gives it, and looks it up
    exactly as APISIX names the owner: an owner in another case would never find it."""
    started = await client.get("/consent", params={"owner": MMAUDET.upper()})

    response = await client.get(lemonldap.sign_in(started.headers["location"], MMAUDET))

    assert response.status_code == 403
    assert await database_dump(database_url) == ""


async def test_a_consent_link_naming_anyone_is_bound_to_them(client: AsyncClient) -> None:
    """A link that names its owner badly fails at the callback, never quietly as the plain one."""
    response = await client.get("/consent", params={"owner": "mmaudet"})

    location = URL(response.headers["location"])
    assert "prompt" not in location.params
    assert location.params["login_hint"] == "mmaudet"


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


async def test_a_drive_delegation_goes_with_the_users_delegation(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    drive: str,
    database_url: str,
) -> None:
    await consent_with_drive(client, lemonldap, cozy_stack, MMAUDET)

    await remove_delegation(database_url, MMAUDET)

    assert await database_dump(database_url) == ""


async def test_a_consent_without_a_drive_instance_completes_for_lemonldap_alone(
    client: AsyncClient, lemonldap: FakeLemonLDAP
) -> None:
    response = await consent(client, lemonldap, MMAUDET)

    assert response.status_code == 200
    assert MMAUDET in response.text
    assert "Drive n&#x27;est pas disponible" in response.text
    authorized = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))
    assert authorized.status_code == 200


async def test_a_consent_completes_for_lemonldap_alone_when_its_userinfo_fails(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    """The consent never fails for Drive: an agent may need LemonLDAP's token alone."""
    lemonldap.userinfo_outage = True

    response = await consent(client, lemonldap, MMAUDET)

    assert response.status_code == 200
    assert "Drive n&#x27;est pas disponible" in response.text
    assert cozy_stack.clients_on(drive) == []


@pytest.mark.parametrize(
    "named",
    [
        f"https://{MMAUDET_DRIVE}/",
        "mmaudet.elsewhere.test",
        "10.0.0.1",
        "kubernetes.default.svc",
        f"drive.{MMAUDET_DRIVE}",
    ],
    ids=["a URL", "another domain", "an IP address", "a cluster service", "below an instance"],
)
async def test_a_workplace_that_is_no_instance_of_the_domain_leaves_drive_out_of_the_consent(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    drive: str,
    named: str,
) -> None:
    """The broker calls the host LemonLDAP names: only an instance of the domain may do."""
    for host in ("mmaudet.elsewhere.test", "10.0.0.1", "kubernetes.default.svc", f"drive.{drive}"):
        cozy_stack.create_instance(host)
    lemonldap.workplaces[MMAUDET] = named

    response = await consent(client, lemonldap, MMAUDET)

    assert response.status_code == 200
    assert "Drive n&#x27;est pas disponible" in response.text


async def test_drive_is_off_without_a_domain_of_drive_instances(
    settings: Settings,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    clock: FakeClock,
    drive: str,
) -> None:
    async with running(
        replace(settings, drive_instance_domain=None), lemonldap, clock, cozy_stack
    ) as broker:
        response = await consent(broker, lemonldap, MMAUDET)

    assert response.status_code == 200
    assert "Drive n&#x27;est pas disponible" in response.text
    assert cozy_stack.clients_on(drive) == []


async def test_an_owner_who_declines_on_their_drive_instance_keeps_the_rest_of_the_consent(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    to_drive = await consent(client, lemonldap, MMAUDET)

    response = await client.get(cozy_stack.refuse(to_drive.headers["location"]))

    assert_authorized_without_drive(response, 200)
    authorized = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))
    assert authorized.status_code == 200


@pytest.mark.parametrize("outage", ["error page", "unreachable"])
async def test_a_drive_instance_that_cannot_register_the_broker_is_a_bad_gateway(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    drive: str,
    outage: Literal["error page", "unreachable"],
) -> None:
    cozy_stack.outage = outage

    response = await consent(client, lemonldap, MMAUDET)

    assert_authorized_without_drive(response, 502)
    authorized = await client.get("/forward-auth", headers=as_agent_of(MMAUDET))
    assert authorized.status_code == 200


async def test_a_drive_callback_whose_state_differs_from_the_consent_in_progress_is_refused(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    to_drive = await consent(client, lemonldap, MMAUDET)
    callback = URL(cozy_stack.authorize(to_drive.headers["location"]))

    response = await client.get(callback.copy_set_param("state", "forged"))

    assert_consent_failed(response)
    unknown = await client.get(
        "/forward-auth", params={"token": "drive"}, headers=as_agent_of(MMAUDET)
    )
    assert unknown.json()["code"] == "delegation_missing"


async def test_a_code_the_drive_instance_refuses_is_refused(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    to_drive = await consent(client, lemonldap, MMAUDET)
    callback = URL(cozy_stack.authorize(to_drive.headers["location"]))

    response = await client.get(callback.copy_set_param("code", "drive-code-unknown"))

    assert_authorized_without_drive(response, 400)


async def test_a_drive_instance_failing_to_complete_the_consent_is_a_bad_gateway(
    client: AsyncClient, lemonldap: FakeLemonLDAP, cozy_stack: FakeCozyStack, drive: str
) -> None:
    to_drive = await consent(client, lemonldap, MMAUDET)
    callback = cozy_stack.authorize(to_drive.headers["location"])
    cozy_stack.outage = "unreachable"

    response = await client.get(callback)

    assert_authorized_without_drive(response, 502)


async def test_a_drive_authorization_whose_delegation_was_removed_meanwhile_is_refused(
    client: AsyncClient,
    lemonldap: FakeLemonLDAP,
    cozy_stack: FakeCozyStack,
    drive: str,
    database_url: str,
) -> None:
    to_drive = await consent(client, lemonldap, MMAUDET)
    callback = cozy_stack.authorize(to_drive.headers["location"])
    await remove_delegation(database_url, MMAUDET)

    response = await client.get(callback)

    assert_consent_failed(response)
    assert await database_dump(database_url) == ""
