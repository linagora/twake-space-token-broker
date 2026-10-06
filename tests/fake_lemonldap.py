"""A fake LemonLDAP, with the sign-in and the token endpoint the broker relies on."""

import base64
import hashlib
import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from urllib.parse import parse_qsl

import httpx

ACCESS_TOKEN_LIFETIME = 36000
"""Seconds an access token lasts, 10 hours as on Twake's LemonLDAP."""


@dataclass(frozen=True)
class _Code:
    user: str
    challenge: str
    redirect_uri: str


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _error(status: int, error: str) -> httpx.Response:
    return httpx.Response(status, json={"error": error})


class FakeLemonLDAP:
    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        client_secret: str,
        let_time_pass: Callable[[float], None],
    ) -> None:
        self._issuer = issuer
        self._client_id = client_id
        self._credentials = (
            "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        )
        self._let_time_pass = let_time_pass
        self.latency = 0.0
        """Seconds each token request takes, which pass on the broker's clock."""
        self._serial = itertools.count(1)
        self._codes: dict[str, _Code] = {}
        self._refresh_tokens: dict[str, str] = {}
        self._access_tokens: dict[str, str] = {}
        self.outage: Literal["error page", "unreachable"] | None = None
        self.grants_offline_access = True
        self.rotates_refresh_tokens = False
        """Twake's LemonLDAP does not rotate them, but another configuration could."""
        self.transport = httpx.MockTransport(self._token_endpoint)

    def sign_in(self, authorize_url: str, user: str) -> str:
        """The user signs in: LemonLDAP sends their browser back with an authorization code."""
        url = httpx.URL(authorize_url)
        assert str(url.copy_with(query=None)) == f"{self._issuer}oauth2/authorize"
        assert url.params["client_id"] == self._client_id
        assert url.params["response_type"] == "code"
        assert url.params["code_challenge_method"] == "S256"
        assert "offline_access" in url.params["scope"].split()
        code = f"code-{next(self._serial)}"
        self._codes[code] = _Code(user, url.params["code_challenge"], url.params["redirect_uri"])
        redirect = httpx.URL(url.params["redirect_uri"])
        return str(redirect.copy_with(params={"code": code, "state": url.params["state"]}))

    def owner_of(self, access_token: str) -> str | None:
        """The user an access token was issued to, if LemonLDAP issued it."""
        return self._access_tokens.get(access_token)

    def refresh_token_of(self, user: str) -> str:
        """The last refresh token issued to the user."""
        return [token for token, owner in self._refresh_tokens.items() if owner == user][-1]

    def end_offline_session(self, user: str) -> None:
        """The user's offline session ends: their refresh tokens die.

        It expires after 30 days, and is deleted with the user on Twake, or by an admin.
        """
        self._refresh_tokens = {
            token: owner for token, owner in self._refresh_tokens.items() if owner != user
        }

    def _token_endpoint(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == f"{self._issuer}oauth2/token"
        self._let_time_pass(self.latency)
        if self.outage == "unreachable":
            raise httpx.ConnectError("Connection refused", request=request)
        if self.outage == "error page":
            return httpx.Response(503, html="<h1>Service Unavailable</h1>")
        if request.headers.get("authorization") != self._credentials:
            return _error(401, "invalid_client")
        form = dict(parse_qsl(request.content.decode()))
        if form.get("grant_type") == "authorization_code":
            return self._redeem(form)
        if form.get("grant_type") == "refresh_token":
            return self._refresh(form)
        return _error(400, "unsupported_grant_type")

    def _redeem(self, form: dict[str, str]) -> httpx.Response:
        code = self._codes.pop(form.get("code", ""), None)
        if code is None or form.get("redirect_uri") != code.redirect_uri:
            return _error(400, "invalid_grant")
        verifier = form.get("code_verifier", "")
        if _encode(hashlib.sha256(verifier.encode()).digest()) != code.challenge:
            return _error(400, "invalid_grant")
        tokens = {**self._access(code.user), "id_token": self._id_token(code.user)}
        if self.grants_offline_access:
            refresh_token = f"refresh-{next(self._serial)}"
            self._refresh_tokens[refresh_token] = code.user
            tokens["refresh_token"] = refresh_token
        return httpx.Response(200, json=tokens)

    def _refresh(self, form: dict[str, str]) -> httpx.Response:
        user = self._refresh_tokens.get(form.get("refresh_token", ""))
        if user is None:
            # As LemonLDAP 2.21 does when it finds no session for the token, logging "Unable to
            # find OIDC session" (_handleRefreshTokenGrant, in Issuer/OpenIDConnect.pm)
            return _error(400, "invalid_request")
        if not self.rotates_refresh_tokens:
            return httpx.Response(200, json=self._access(user))
        del self._refresh_tokens[form["refresh_token"]]
        rotated = f"refresh-{next(self._serial)}"
        self._refresh_tokens[rotated] = user
        return httpx.Response(200, json={**self._access(user), "refresh_token": rotated})

    def _access(self, user: str) -> dict[str, str | int]:
        access_token = f"access-{next(self._serial)}"
        self._access_tokens[access_token] = user
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_LIFETIME,
            "scope": "openid email",
        }

    def _id_token(self, user: str) -> str:
        """A JWT whose signature the broker has no need to check, as it comes from LemonLDAP."""
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {"iss": self._issuer, "aud": self._client_id, "sub": user}
        return ".".join(
            [_encode(json.dumps(header).encode()), _encode(json.dumps(claims).encode()), "c2ln"]
        )
