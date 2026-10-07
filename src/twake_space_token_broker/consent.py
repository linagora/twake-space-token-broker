"""The consent link, through which a user lets their agent act for them.

The consent runs in two steps that both come back to /callback: the user signs in to LemonLDAP,
then, when LemonLDAP names their Drive instance, lets the broker in on that instance. A link bound
to its owner checks that the account that signed in is theirs.
"""

import logging
import secrets
from collections.abc import Callable
from html import escape
from typing import Annotated, Any

from fastapi import APIRouter, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from twake_space_token_broker.consent_links import CONSENT, consent_link
from twake_space_token_broker.cozy_stack import InstanceRefused, InstanceUnavailable
from twake_space_token_broker.drive import DriveTokens
from twake_space_token_broker.keys import Signer
from twake_space_token_broker.lemonldap import (
    GrantRefused,
    LemonLDAP,
    LemonLDAPUnavailable,
    OfflineAccessDenied,
    SignedIn,
)
from twake_space_token_broker.tokens import AccessTokens, DelegationMissing

logger = logging.getLogger(__name__)

COOKIE = "twake_space_consent"
COOKIE_LIFETIME = 600
"""Seconds a user has to sign in once the consent has started, and to accept on their Drive."""

COOKIE_KEPT = 3600
"""Seconds the browser keeps the cookie of a consent.

Longer than the consent lasts, so that a consent that expired still starts over from its owner's
link.
"""

DRIVE_STEP = "drive"
"""The step of a consent in progress whose user is on their Drive instance."""

UNAVAILABLE = "Votre instance Drive n'a pas pu terminer l'autorisation."


def _page(
    title: str, message: str, *, retry_url: str | None = None, status_code: int = 200
) -> HTMLResponse:
    """A short page in French.

    Its title and message are text, which the page escapes. With a retry URL, a link lets the user
    start the consent over.
    """
    link = f'\n<p><a href="{escape(retry_url)}">Recommencer</a></p>' if retry_url else ""
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


def _refused(reason: str, *, retry_url: str, status_code: int = 400) -> HTMLResponse:
    response = _page(
        "L'autorisation n'a pas abouti", reason, retry_url=retry_url, status_code=status_code
    )
    response.delete_cookie(COOKIE)
    return response


def _authorized(message: str) -> HTMLResponse:
    response = _page("Votre assistant est autorisé", f"{message} Vous pouvez fermer cette page.")
    response.delete_cookie(COOKIE)
    return response


def _without_drive(user: str, reason: str, *, retry_url: str, status_code: int) -> HTMLResponse:
    """The user's agent may act for them, but not in Drive: they learn why, and may retry."""
    response = _page(
        "Votre assistant est autorisé, sauf dans Drive",
        f"Votre assistant Twake Space peut désormais agir pour {user}, mais pas dans Drive."
        f" {reason}",
        retry_url=retry_url,
        status_code=status_code,
    )
    response.delete_cookie(COOKIE)
    return response


def _wrong_account(owner: str, signed_in: str) -> HTMLResponse:
    """The browser is signed in as another account than the one the link is for."""
    response = _page(
        "Ce lien est pour un autre compte",
        f"Ce lien autorise l'assistant de {owner}, mais ce navigateur est connecté à Twake en"
        f" tant que {signed_in} : rien n'a été enregistré. Ouvrez ce lien dans une fenêtre de"
        f" navigation privée, puis connectez-vous en tant que {owner}.",
        retry_url=consent_link(owner),
        status_code=403,
    )
    response.delete_cookie(COOKIE)
    return response


def _retry_url(owner: str | None) -> str:
    """Where a failed consent starts over: from its owner's link, when it had one."""
    return consent_link(owner) if owner else CONSENT


def _owner(value: str | None) -> str | None:
    """The owner a consent link names, or None for the plain link.

    It is kept exactly as given, as the broker keys and looks up delegations by email exactly.
    """
    return (value or "").strip() or None


def _same_state(flow: dict[str, Any], state: str | None) -> bool:
    return secrets.compare_digest(flow["state"].encode(), (state or "").encode())


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
            max_age=COOKIE_KEPT,
            httponly=True,
            secure=True,
            samesite="lax",
        )

    @routes.get(CONSENT)
    async def consent(owner: str | None = None) -> RedirectResponse:
        """Starts a consent, bound to its owner when the link names them."""
        owner = _owner(owner)
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        response = RedirectResponse(
            lemonldap.authorize_url(state=state, verifier=verifier, owner=owner),
            status_code=302,
        )
        remember(response, {"state": state, "verifier": verifier, "owner": owner})
        return response

    @routes.get("/callback")
    async def callback(
        code: str | None = None,
        state: str | None = None,
        started: Annotated[str | None, Cookie(alias=COOKIE)] = None,
    ) -> Response:
        flow = signer.verify(started) if started else None
        if flow is None:
            return _refused(
                "Aucune autorisation n'est en cours dans ce navigateur.", retry_url=CONSENT
            )
        retry_url = _retry_url(flow.get("owner"))
        if clock() >= flow["expires"]:
            return _refused("L'autorisation a expiré.", retry_url=retry_url)
        if flow.get("step") == DRIVE_STEP:
            return await drive_callback(flow, code, state)
        if not _same_state(flow, state):
            return _refused(
                "Cette page ne correspond pas à l'autorisation en cours.", retry_url=retry_url
            )
        if code is None:
            return _refused("LemonLDAP n'a pas accordé l'autorisation.", retry_url=retry_url)
        try:
            signed_in = await lemonldap.redeem(code, flow["verifier"])
        except GrantRefused:
            return _refused("LemonLDAP a refusé le code d'autorisation.", retry_url=retry_url)
        except LemonLDAPUnavailable as unavailable:
            logger.warning("LemonLDAP completed no consent: %s", unavailable)
            return _refused(
                "LemonLDAP n'a pas pu terminer l'autorisation.",
                retry_url=retry_url,
                status_code=502,
            )
        except OfflineAccessDenied:
            logger.warning("LemonLDAP granted no offline access: check the client's options")
            return _refused(
                "LemonLDAP n'a pas accordé d'accès hors ligne à l'assistant.",
                retry_url=retry_url,
                status_code=502,
            )
        owner = flow.get("owner")
        if owner is not None and signed_in.user != owner:
            # A browser still signed in as someone else, as LemonLDAP's "stay connected" keeps it:
            # nothing is stored, and that account's own delegations stay as they were
            logger.warning(
                "A consent for %s came back signed in as %s: nothing stored", owner, signed_in.user
            )
            return _wrong_account(owner, signed_in.user)
        await access_tokens.consented(signed_in)
        # The new consent replaces the whole delegation: Drive comes back only if granted again
        await drive_tokens.forget(signed_in.user)
        return await to_drive(signed_in, owner)

    async def to_drive(signed_in: SignedIn, owner: str | None) -> Response:
        """Sends the user on to their Drive instance, if LemonLDAP names one.

        A consent bound to its owner stays bound through the Drive step.
        """
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
        try:
            authorize_url = await drive_tokens.request(
                signed_in.user, instance, state=state, verifier=verifier
            )
        except InstanceUnavailable as unavailable:
            logger.warning(
                "The Drive instance of %s took no client: %s", signed_in.user, unavailable
            )
            return _without_drive(
                signed_in.user, UNAVAILABLE, retry_url=_retry_url(owner), status_code=502
            )
        response = RedirectResponse(authorize_url, status_code=302)
        remember(
            response,
            {
                "step": DRIVE_STEP,
                "user": signed_in.user,
                "owner": owner,
                "state": state,
                "verifier": verifier,
            },
        )
        return response

    async def drive_callback(flow: dict[str, Any], code: str | None, state: str | None) -> Response:
        """Where the user's Drive instance sends them back."""
        user = flow["user"]
        retry_url = _retry_url(flow.get("owner"))
        if code is None:
            # The instance's page links back with no state when the user declines: the answer
            # changes nothing the broker keeps
            return _without_drive(
                user,
                "Vous n'avez pas accordé l'accès à vos fichiers.",
                status_code=200,
                retry_url=retry_url,
            )
        if not _same_state(flow, state):
            return _refused(
                "Cette page ne correspond pas à l'autorisation en cours.", retry_url=retry_url
            )
        try:
            await drive_tokens.consented(user, code, flow["verifier"])
        except DelegationMissing:
            return _refused("Cette autorisation n'est plus en cours.", retry_url=retry_url)
        except InstanceRefused:
            return _without_drive(
                user,
                "Votre instance Drive a refusé le code d'autorisation.",
                status_code=400,
                retry_url=retry_url,
            )
        except InstanceUnavailable as unavailable:
            logger.warning("The Drive instance of %s completed no consent: %s", user, unavailable)
            return _without_drive(user, UNAVAILABLE, status_code=502, retry_url=retry_url)
        return _authorized(
            f"Votre assistant Twake Space peut désormais agir pour {user}, y compris dans Drive."
        )

    return routes
