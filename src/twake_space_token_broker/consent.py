"""The fixed consent link, through which a user lets their agent act for them."""

import base64
import hashlib
import secrets
from html import escape
from typing import Annotated

from fastapi import APIRouter, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse

from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.keys import Signer
from twake_space_token_broker.lemonldap import LemonLDAP

COOKIE = "twake_space_consent"
COOKIE_LIFETIME = 600
"""Seconds a user has to sign in once the consent has started."""


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _page(title: str, message: str, *, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
</head>
<body>
<main>
<h1>{escape(title)}</h1>
<p>{message}</p>
</main>
</body>
</html>
""",
        status_code=status_code,
    )


def router(lemonldap: LemonLDAP, signer: Signer, delegations: Delegations) -> APIRouter:
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

    @routes.get("/callback")
    async def callback(code: str, started: Annotated[str, Cookie(alias=COOKIE)]) -> HTMLResponse:
        flow = signer.verify(started) or {}
        signed_in = await lemonldap.redeem(code, flow["verifier"])
        assert signed_in.tokens.refresh_token is not None
        await delegations.save(signed_in.user, signed_in.tokens.refresh_token)
        response = _page(
            "Votre assistant est autorisé",
            f"Votre assistant Twake Space peut désormais agir pour {escape(signed_in.user)}."
            " Vous pouvez fermer cette page.",
        )
        response.delete_cookie(COOKIE)
        return response

    return routes
