"""The forward-auth endpoint APISIX calls before relaying an agent's call to a contract."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response

from twake_space_token_broker.cozy_stack import InstanceUnavailable
from twake_space_token_broker.drive import DriveTokens
from twake_space_token_broker.lemonldap import LemonLDAPUnavailable
from twake_space_token_broker.problems import Problem
from twake_space_token_broker.tokens import AccessTokens, DelegationExpired, DelegationMissing

logger = logging.getLogger(__name__)

DRIVE = "drive"
"""The token a Drive route asks for, with ?token=drive."""


def _owner(
    x_twake_user_email: Annotated[str | None, Header()] = None,
) -> str:
    """The email of the agent's owner, which APISIX sets from the agent's consumer."""
    if not x_twake_user_email:
        raise Problem(
            status=400,
            code="missing_user_email",
            title="Missing user email",
            detail="The X-Twake-User-Email header must name the agent's owner.",
        )
    return x_twake_user_email


Owner = Annotated[str, Depends(_owner)]


def router(access_tokens: AccessTokens, drive_tokens: DriveTokens, consent_url: str) -> APIRouter:
    routes = APIRouter()

    @routes.get("/forward-auth")
    async def forward_auth(owner: Owner, token: str | None = None) -> Response:
        """Answers with the owner's access token, which APISIX passes on to the contract, and with
        a token of their Drive instance when the route asks for it."""
        if token not in (None, DRIVE):
            raise Problem(
                status=400,
                code="unknown_token",
                title="Unknown token",
                detail="The token query parameter can only ask for drive.",
            )
        try:
            # LemonLDAP's token first: it names the owner to the contract, and a delegation
            # LemonLDAP no longer honours gives no Drive token either
            headers = {"Authorization": f"Bearer {await access_tokens.of(owner)}"}
            if token == DRIVE:
                drive = await drive_tokens.of(owner)
                headers["X-Twake-Drive-Token"] = drive.access_token
                headers["X-Twake-Drive-Instance"] = drive.instance
        except DelegationMissing as missing:
            raise Problem(
                status=401,
                code="delegation_missing",
                title="Delegation missing",
                detail="The user has not let their agent act for them yet: they must open the"
                " consent link.",
                extensions={"consent_url": consent_url},
            ) from missing
        except DelegationExpired as expired:
            raise Problem(
                status=401,
                code="delegation_expired",
                title="Delegation expired",
                detail="The user's consent to their agent is no longer valid: they must open"
                " the consent link again.",
                extensions={"consent_url": consent_url},
            ) from expired
        except LemonLDAPUnavailable as unavailable:
            logger.warning("LemonLDAP refreshed no token for %s: %s", owner, unavailable)
            raise Problem(
                status=502,
                code="lemonldap_unavailable",
                title="LemonLDAP unavailable",
                detail="LemonLDAP did not answer the token request: try again later.",
            ) from unavailable
        except InstanceUnavailable as unavailable:
            logger.warning("The Drive instance of %s refreshed no token: %s", owner, unavailable)
            raise Problem(
                status=502,
                code="drive_unavailable",
                title="Drive unavailable",
                detail="The owner's Drive instance did not answer the token request: try again"
                " later.",
            ) from unavailable
        return Response(headers=headers)

    return routes
