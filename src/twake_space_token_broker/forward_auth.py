"""The forward-auth endpoint APISIX calls before relaying an agent's call to a contract."""

from typing import Annotated

from fastapi import APIRouter, Header, Response

from twake_space_token_broker.tokens import AccessTokens


def router(tokens: AccessTokens) -> APIRouter:
    routes = APIRouter()

    @routes.get("/forward-auth")
    async def forward_auth(x_twake_user_email: Annotated[str, Header()]) -> Response:
        """Answers with the owner's access token, which APISIX passes on to the contract."""
        access_token = await tokens.of(x_twake_user_email)
        return Response(headers={"Authorization": f"Bearer {access_token}"})

    return routes
