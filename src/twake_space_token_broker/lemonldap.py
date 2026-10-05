"""LemonLDAP, the OpenID Connect provider, as the broker's own client sees it."""

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from twake_space_token_broker.settings import Settings

SCOPE = "openid email offline_access"


class GrantRefused(Exception):
    """LemonLDAP refused a code or a refresh token, which can no longer give any token."""


class LemonLDAPUnavailable(Exception):
    """LemonLDAP gave no usable answer, so the same request may work later."""


class OfflineAccessDenied(Exception):
    """LemonLDAP issued no refresh token, so the broker could never act for the user later."""


@dataclass(frozen=True)
class Tokens:
    access_token: str
    expires_at: float
    """When the access token expires, in seconds since the epoch."""
    refresh_token: str | None


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
    payload = id_token.split(".")[1]
    claims: dict[str, Any] = json.loads(
        base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    )
    return str(claims["sub"])


def _json(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _tokens(body: dict[str, Any], requested_at: float) -> Tokens:
    return Tokens(
        access_token=body["access_token"],
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

    def authorize_url(self, *, state: str, code_challenge: str) -> str:
        """Where the user signs in, to grant the broker offline access with PKCE."""
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._settings.client_id,
                "redirect_uri": self._settings.redirect_uri,
                "scope": SCOPE,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{self._endpoint('authorize')}?{query}"

    async def redeem(self, code: str, verifier: str) -> SignedIn:
        """Exchanges the code LemonLDAP sent the user back with for their tokens."""
        tokens, body = await self._token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._settings.redirect_uri,
                "code_verifier": verifier,
            }
        )
        if tokens.refresh_token is None:
            raise OfflineAccessDenied()
        try:
            user = _subject(body["id_token"])
        except (KeyError, IndexError, ValueError) as error:
            raise LemonLDAPUnavailable("an answer without the user's identity") from error
        return SignedIn(user=user, refresh_token=tokens.refresh_token, tokens=tokens)

    async def refresh(self, refresh_token: str) -> Tokens:
        """A new access token for the user the refresh token was issued to."""
        tokens, _ = await self._token(
            {"grant_type": "refresh_token", "refresh_token": refresh_token}
        )
        return tokens

    async def _token(self, form: dict[str, str]) -> tuple[Tokens, dict[str, Any]]:
        requested_at = self._clock()
        try:
            response = await self._http.post(
                self._endpoint("token"),
                data=form,
                auth=(self._settings.client_id, self._settings.client_secret),
            )
        except httpx.HTTPError as error:
            raise LemonLDAPUnavailable(f"no answer ({type(error).__name__})") from error
        body = _json(response)
        if response.status_code == 400 and body.get("error") == "invalid_grant":
            raise GrantRefused()
        if response.status_code != 200:
            raise LemonLDAPUnavailable(f"HTTP {response.status_code} {body.get('error', '')}")
        try:
            return _tokens(body, requested_at), body
        except (KeyError, TypeError, ValueError) as error:
            raise LemonLDAPUnavailable("an answer without tokens") from error
