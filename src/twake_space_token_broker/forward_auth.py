"""The forward-auth endpoint APISIX calls before relaying an agent's call to a contract."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Response

from twake_space_token_broker.lemonldap import LemonLDAPUnavailable
from twake_space_token_broker.problems import Problem
from twake_space_token_broker.tokens import AccessTokens, DelegationExpired, DelegationMissing

logger = logging.getLogger(__name__)


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


def router(tokens: AccessTokens, consent_url: str) -> APIRouter:
    routes = APIRouter()

    @routes.get("/forward-auth")
    async def forward_auth(owner: Owner) -> Response:
        """Answers with the owner's access token, which APISIX passes on to the contract."""
        try:
            access_token = await tokens.of(owner)
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
                detail="The user's consent to their agent has expired: they must open the"
                " consent link again.",
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
        return Response(headers={"Authorization": f"Bearer {access_token}"})

    return routes
