"""LemonLDAP, the OpenID Connect provider, as the broker's own client sees it."""

import base64
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from twake_space_token_broker.settings import Settings

SCOPE = "openid email offline_access"


class GrantRefused(Exception):
    """LemonLDAP refused a code or a refresh token, which can no longer give any token."""


@dataclass(frozen=True)
class Tokens:
    access_token: str
    expires_in: int
    """Seconds the access token lasts from when LemonLDAP issued it."""
    refresh_token: str | None


@dataclass(frozen=True)
class SignedIn:
    user: str
    """The user's email, which is the subject LemonLDAP names its users by on Twake."""
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


def _tokens(body: dict[str, Any]) -> Tokens:
    return Tokens(
        access_token=body["access_token"],
        expires_in=int(body["expires_in"]),
        refresh_token=body.get("refresh_token"),
    )


class LemonLDAP:
    def __init__(self, settings: Settings, http: httpx.AsyncClient) -> None:
        self._settings = settings
        self._http = http

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
        body = await self._token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._settings.redirect_uri,
                "code_verifier": verifier,
            }
        )
        return SignedIn(user=_subject(body["id_token"]), tokens=_tokens(body))

    async def refresh(self, refresh_token: str) -> Tokens:
        """A new access token for the user the refresh token was issued to."""
        return _tokens(
            await self._token({"grant_type": "refresh_token", "refresh_token": refresh_token})
        )

    async def _token(self, form: dict[str, str]) -> dict[str, Any]:
        response = await self._http.post(
            self._endpoint("token"),
            data=form,
            auth=(self._settings.client_id, self._settings.client_secret),
        )
        body: dict[str, Any] = response.json()
        if response.status_code == 400 and body.get("error") == "invalid_grant":
            raise GrantRefused()
        return body
