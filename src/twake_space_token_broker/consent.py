"""The fixed consent link, through which a user lets their agent act for them."""

import logging
import secrets
from collections.abc import Callable
from html import escape
from typing import Annotated

from fastapi import APIRouter, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse

from twake_space_token_broker.keys import Signer
from twake_space_token_broker.lemonldap import (
    GrantRefused,
    LemonLDAP,
    LemonLDAPUnavailable,
    OfflineAccessDenied,
)
from twake_space_token_broker.tokens import AccessTokens

logger = logging.getLogger(__name__)

COOKIE = "twake_space_consent"
COOKIE_LIFETIME = 600
"""Seconds a user has to sign in once the consent has started."""


def _page(title: str, message: str, *, retry: bool = False, status_code: int = 200) -> HTMLResponse:
    """A short page in French. Its title and message are text, which the page escapes."""
    link = '\n<p><a href="/consent">Recommencer</a></p>' if retry else ""
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
<p>{escape(message)}</p>{link}
</main>
</body>
</html>
""",
        status_code=status_code,
    )


def _refused(reason: str, *, status_code: int = 400) -> HTMLResponse:
    response = _page("L'autorisation n'a pas abouti", reason, retry=True, status_code=status_code)
    response.delete_cookie(COOKIE)
    return response


def router(
    lemonldap: LemonLDAP,
    signer: Signer,
    access_tokens: AccessTokens,
    clock: Callable[[], float],
) -> APIRouter:
    routes = APIRouter()

    @routes.get("/consent")
    async def consent() -> RedirectResponse:
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        response = RedirectResponse(
            lemonldap.authorize_url(state=state, verifier=verifier),
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
        code: str | None = None,
        state: str | None = None,
        started: Annotated[str | None, Cookie(alias=COOKIE)] = None,
    ) -> HTMLResponse:
        flow = signer.verify(started) if started else None
        if flow is None:
            return _refused("Aucune autorisation n'est en cours dans ce navigateur.")
        if clock() >= flow["expires"]:
            return _refused("L'autorisation a expiré.")
        if not secrets.compare_digest(flow["state"].encode(), (state or "").encode()):
            return _refused("Cette page ne correspond pas à l'autorisation en cours.")
        if code is None:
            return _refused("LemonLDAP n'a pas accordé l'autorisation.")
        try:
            signed_in = await lemonldap.redeem(code, flow["verifier"])
        except GrantRefused:
            return _refused("LemonLDAP a refusé le code d'autorisation.")
        except LemonLDAPUnavailable as unavailable:
            logger.warning("LemonLDAP completed no consent: %s", unavailable)
            return _refused("LemonLDAP n'a pas pu terminer l'autorisation.", status_code=502)
        except OfflineAccessDenied:
            logger.warning("LemonLDAP granted no offline access: check the client's options")
            return _refused(
                "LemonLDAP n'a pas accordé d'accès hors ligne à l'assistant.", status_code=502
            )
        await access_tokens.consented(signed_in)
        response = _page(
            "Votre assistant est autorisé",
            f"Votre assistant Twake Space peut désormais agir pour {signed_in.user}."
            " Vous pouvez fermer cette page.",
        )
        response.delete_cookie(COOKIE)
        return response

    return routes
