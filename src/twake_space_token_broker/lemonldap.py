"""LemonLDAP, the OpenID Connect provider, as the broker's own client sees it."""

import json
import logging
import re
from collections.abc import Callable, Set
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from twake_space_token_broker import base64url, pkce
from twake_space_token_broker.oauth import Tokens, json_object
from twake_space_token_broker.settings import LABEL, Settings

logger = logging.getLogger(__name__)

SCOPE = "openid email offline_access"

DRIVE_INSTANCE_CLAIM = "workplaceFqdn"
"""The claim naming the host of the user's Drive instance, which the directory keeps."""


class GrantRefused(Exception):
    """LemonLDAP refused a code or a refresh token.

    A refused refresh token may work again after an outage of LemonLDAP's LDAP directory or
    session store, during which LemonLDAP answers the same errors.
    """


class LemonLDAPUnavailable(Exception):
    """LemonLDAP gave no usable answer, so the same request may work later."""


class OfflineAccessDenied(Exception):
    """LemonLDAP issued no refresh token, so the broker could never act for the user later."""


@dataclass(frozen=True)
class SignedIn:
    user: str
    """The user's email, which is the subject LemonLDAP names its users by on Twake."""
    refresh_token: str
    tokens: Tokens


def _subject(id_token: str) -> str:
    """The subject of an ID token straight from LemonLDAP's token endpoint.

    It comes over TLS from the issuer, in answer to the broker's own credentials, so the
    signature needs no check (OpenID Connect Core, 3.1.3.7).
    """
    claims: dict[str, Any] = json.loads(base64url.decode(id_token.split(".")[1]))
    return str(claims["sub"])


def _tokens(body: dict[str, Any], requested_at: float) -> Tokens:
    return Tokens(
        access_token=body["access_token"],
        requested_at=requested_at,
        expires_at=requested_at + int(body["expires_in"]),
        refresh_token=body.get("refresh_token"),
    )


class LemonLDAP:
    def __init__(
        self, settings: Settings, http: httpx.AsyncClient, clock: Callable[[], float]
    ) -> None:
        self._settings = settings
        self._http = http
        self._clock = clock

    def _endpoint(self, path: str) -> str:
        return f"{self._settings.issuer.rstrip('/')}/oauth2/{path}"

    def authorize_url(self, *, state: str, verifier: str, owner: str | None = None) -> str:
        """Where the user signs in, to grant the broker offline access with PKCE.

        For a consent link bound to its owner, the callback checks who signed in, so an open SSO
        session of the owner serves as is. Otherwise LemonLDAP has the user sign in again, which
        its "stay connected" defeats: that login counts as a fresh one.
        """
        params = {
            "response_type": "code",
            "client_id": self._settings.client_id,
            "redirect_uri": self._settings.redirect_uri,
            "scope": SCOPE,
            "state": state,
            "code_challenge": pkce.challenge(verifier),
            "code_challenge_method": "S256",
        }
        if owner is None:
            # An open SSO session may be someone else's
            params["prompt"] = "login"
        else:
            params["login_hint"] = owner
        return f"{self._endpoint('authorize')}?{urlencode(params)}"

    async def redeem(self, code: str, verifier: str) -> SignedIn:
        """Exchanges the code LemonLDAP sent the user back with for their tokens."""
        tokens, body = await self._token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._settings.redirect_uri,
                "code_verifier": verifier,
            },
            refused_with={"invalid_grant"},
        )
        if tokens.refresh_token is None:
            raise OfflineAccessDenied()
        try:
            user = _subject(body["id_token"])
        except (KeyError, IndexError, ValueError) as error:
            raise LemonLDAPUnavailable("an answer without the user's identity") from error
        return SignedIn(user=user, refresh_token=tokens.refresh_token, tokens=tokens)

    async def drive_instance(self, access_token: str) -> str | None:
        """The host of the user's Drive instance, if LemonLDAP names in their userinfo one under
        the domain of the users' instances."""
        domain = self._settings.drive_instance_domain
        if domain is None:
            return None
        try:
            response = await self._http.get(
                self._endpoint("userinfo"), headers={"Authorization": f"Bearer {access_token}"}
            )
        except httpx.HTTPError as error:
            raise LemonLDAPUnavailable(f"no answer ({type(error).__name__})") from error
        body = json_object(response)
        if response.status_code != 200 or not body:
            raise LemonLDAPUnavailable(f"HTTP {response.status_code} {body.get('error', '')}")
        host = body.get(DRIVE_INSTANCE_CLAIM)
        if host is None:
            return None
        # The broker calls the instance at this host: nothing but one of the users' instances,
        # never an address, a service of the cluster or a host elsewhere
        if not isinstance(host, str) or not re.fullmatch(
            rf"{LABEL}\.{re.escape(domain)}", host.lower()
        ):
            logger.warning("LemonLDAP names a Drive instance outside %s: %r", domain, host)
            return None
        return host.lower()

    async def refresh(self, refresh_token: str) -> Tokens:
        """A new access token for the user the refresh token was issued to."""
        tokens, _ = await self._token(
            {"grant_type": "refresh_token", "refresh_token": refresh_token},
            # LemonLDAP 2.21 answers invalid_request when it finds no session for the token, as
            # once the offline session expired or was deleted, and invalid_grant when the user
            # is no longer in LDAP
            refused_with={"invalid_request", "invalid_grant"},
        )
        return tokens

    async def _token(
        self, form: dict[str, str], *, refused_with: Set[str]
    ) -> tuple[Tokens, dict[str, Any]]:
        """Tokens from LemonLDAP's token endpoint.

        A 400 with one of the errors in refused_with refuses the grant. Any other error says
        nothing of the grant, so the same request may work later.
        """
        requested_at = self._clock()
        try:
            response = await self._http.post(
                self._endpoint("token"),
                data=form,
                auth=(self._settings.client_id, self._settings.client_secret),
            )
        except httpx.HTTPError as error:
            raise LemonLDAPUnavailable(f"no answer ({type(error).__name__})") from error
        body = json_object(response)
        if response.status_code == 400 and body.get("error") in refused_with:
            raise GrantRefused(body["error"])
        if response.status_code != 200:
            raise LemonLDAPUnavailable(f"HTTP {response.status_code} {body.get('error', '')}")
        try:
            return _tokens(body, requested_at), body
        except (KeyError, TypeError, ValueError) as error:
            raise LemonLDAPUnavailable("an answer without tokens") from error
