"""The fixed consent link, through which a user lets their agent act for them."""

import base64
import hashlib
import secrets

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

from twake_space_token_broker.keys import Signer
from twake_space_token_broker.lemonldap import LemonLDAP

COOKIE = "twake_space_consent"
COOKIE_LIFETIME = 600
"""Seconds a user has to sign in once the consent has started."""


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def router(lemonldap: LemonLDAP, signer: Signer) -> APIRouter:
    routes = APIRouter()

    @routes.get("/consent")
    async def consent() -> RedirectResponse:
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        response = RedirectResponse(
            lemonldap.authorize_url(state=state, code_challenge=_challenge(verifier)),
            status_code=302,
        )
        response.set_cookie(
            COOKIE,
            signer.sign({"state": state, "verifier": verifier}),
            max_age=COOKIE_LIFETIME,
            httponly=True,
            secure=True,
            samesite="lax",
        )
        return response

    return routes
