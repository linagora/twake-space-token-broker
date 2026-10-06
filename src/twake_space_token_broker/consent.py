"""The fixed consent link, through which a user lets their agent act for them.

The consent runs in two steps that both come back to /callback: the user signs in to LemonLDAP,
then, when LemonLDAP names their Drive instance, lets the broker in on that instance.
"""

import logging
import secrets
from collections.abc import Callable
from html import escape
from typing import Annotated, Any

from fastapi import APIRouter, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from twake_space_token_broker.drive import DriveTokens
from twake_space_token_broker.keys import Signer
from twake_space_token_broker.lemonldap import (
    GrantRefused,
    LemonLDAP,
    LemonLDAPUnavailable,
    OfflineAccessDenied,
    SignedIn,
)
from twake_space_token_broker.tokens import AccessTokens

logger = logging.getLogger(__name__)

COOKIE = "twake_space_consent"
COOKIE_LIFETIME = 600
"""Seconds a user has to sign in once the consent has started, and to accept on their Drive."""

DRIVE_STEP = "drive"
"""The step of a consent in progress whose user is on their Drive instance."""


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


def _authorized(message: str) -> HTMLResponse:
    response = _page("Votre assistant est autorisé", f"{message} Vous pouvez fermer cette page.")
    response.delete_cookie(COOKIE)
    return response


def router(
    lemonldap: LemonLDAP,
    signer: Signer,
    access_tokens: AccessTokens,
    drive_tokens: DriveTokens,
    clock: Callable[[], float],
) -> APIRouter:
    routes = APIRouter()

    def remember(response: Response, flow: dict[str, Any]) -> None:
        """Keeps the step in progress in the user's browser, signed, until it expires."""
        expires = clock() + COOKIE_LIFETIME
        response.set_cookie(
            COOKIE,
            signer.sign({**flow, "expires": expires}),
            max_age=COOKIE_LIFETIME,
            httponly=True,
            secure=True,
            samesite="lax",
        )

    @routes.get("/consent")
    async def consent() -> RedirectResponse:
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        response = RedirectResponse(
            lemonldap.authorize_url(state=state, verifier=verifier),
            status_code=302,
        )
        remember(response, {"state": state, "verifier": verifier})
        return response

    @routes.get("/callback")
    async def callback(
        code: str | None = None,
        state: str | None = None,
        started: Annotated[str | None, Cookie(alias=COOKIE)] = None,
    ) -> Response:
        flow = signer.verify(started) if started else None
        if flow is None:
            return _refused("Aucune autorisation n'est en cours dans ce navigateur.")
        if clock() >= flow["expires"]:
            return _refused("L'autorisation a expiré.")
        if not secrets.compare_digest(flow["state"].encode(), (state or "").encode()):
            return _refused("Cette page ne correspond pas à l'autorisation en cours.")
        if flow.get("step") == DRIVE_STEP:
            return await drive_callback(flow["user"], code, flow["verifier"])
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
        return await to_drive(signed_in)

    async def to_drive(signed_in: SignedIn) -> Response:
        """Sends the user on to their Drive instance, if LemonLDAP names one."""
        try:
            instance = await lemonldap.drive_instance(signed_in.tokens.access_token)
        except LemonLDAPUnavailable as unavailable:
            # The agent may need LemonLDAP's token alone: Drive never fails the consent
            logger.warning(
                "LemonLDAP named no Drive instance of %s: %s", signed_in.user, unavailable
            )
            instance = None
        if instance is None:
            return _authorized(
                f"Votre assistant Twake Space peut désormais agir pour {signed_in.user}."
                " Drive n'est pas disponible pour votre compte."
            )
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        authorize_url = await drive_tokens.request(
            signed_in.user, instance, state=state, verifier=verifier
        )
        response = RedirectResponse(authorize_url, status_code=302)
        remember(
            response,
            {"step": DRIVE_STEP, "user": signed_in.user, "state": state, "verifier": verifier},
        )
        return response

    async def drive_callback(user: str, code: str | None, verifier: str) -> Response:
        """Where the user's Drive instance sends them back."""
        if code is None:
            return _refused("Votre instance Drive n'a pas accordé l'autorisation.")
        await drive_tokens.consented(user, code, verifier)
        return _authorized(
            f"Votre assistant Twake Space peut désormais agir pour {user}, y compris dans Drive."
        )

    return routes
