"""The fixed consent link, through which a user lets their agent act for them."""

import base64
import hashlib
import secrets
from collections.abc import Callable
from html import escape
from typing import Annotated

from fastapi import APIRouter, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse

from twake_space_token_broker.keys import Signer
from twake_space_token_broker.lemonldap import LemonLDAP
from twake_space_token_broker.tokens import AccessTokens

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


def _refused(reason: str) -> HTMLResponse:
    response = _page(
        "L'autorisation n'a pas abouti",
        f'{escape(reason)} <a href="/consent">Recommencer</a>',
        status_code=400,
    )
    response.delete_cookie(COOKIE)
    return response


def router(
    lemonldap: LemonLDAP, signer: Signer, tokens: AccessTokens, clock: Callable[[], float]
) -> APIRouter:
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
            signer.sign(
                {"state": state, "verifier": verifier, "expires": clock() + COOKIE_LIFETIME}
            ),
            max_age=COOKIE_LIFETIME,
            httponly=True,
            secure=True,
            samesite="lax",
        )
        return response

    @routes.get("/callback")
    async def callback(
        code: str, state: str, started: Annotated[str | None, Cookie(alias=COOKIE)] = None
    ) -> HTMLResponse:
        flow = signer.verify(started) if started else None
        if flow is None:
            return _refused("Aucune autorisation n'est en cours dans ce navigateur.")
        if clock() >= flow["expires"]:
            return _refused("L'autorisation a expiré.")
        if not secrets.compare_digest(str(flow.get("state", "")).encode(), state.encode()):
            return _refused("Cette page ne correspond pas à l'autorisation en cours.")
        signed_in = await lemonldap.redeem(code, flow["verifier"])
        await tokens.consented(signed_in)
        response = _page(
            "Votre assistant est autorisé",
            f"Votre assistant Twake Space peut désormais agir pour {escape(signed_in.user)}."
            " Vous pouvez fermer cette page.",
        )
        response.delete_cookie(COOKIE)
        return response

    return routes
