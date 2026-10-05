"""The forward-auth endpoint APISIX calls before relaying an agent's call to a contract."""

from typing import Annotated

from fastapi import APIRouter, Header, Response

from twake_space_token_broker.problems import Problem
from twake_space_token_broker.tokens import AccessTokens, DelegationExpired


def router(tokens: AccessTokens, consent_url: str) -> APIRouter:
    routes = APIRouter()

    @routes.get("/forward-auth")
    async def forward_auth(x_twake_user_email: Annotated[str, Header()]) -> Response:
        """Answers with the owner's access token, which APISIX passes on to the contract."""
        try:
            access_token = await tokens.of(x_twake_user_email)
        except DelegationExpired as expired:
            raise Problem(
                status=401,
                code="delegation_expired",
                title="Delegation expired",
                detail="The user's consent to their agent has expired: they must open the"
                " consent link again.",
                extensions={"consent_url": consent_url},
            ) from expired
        return Response(headers={"Authorization": f"Bearer {access_token}"})

    return routes
