"""cozy-stack, the server of each user's Drive instance, as the broker's OAuth client sees it."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx

from twake_space_token_broker import pkce
from twake_space_token_broker.lemonldap import Tokens

SCOPE = "io.cozy.files:GET,POST"
"""Reading and creating files, as the agents' Drive contracts do: never the whole instance."""

CLIENT_NAME = "Assistant Twake Space"
"""How the instance names the broker to its owner, on its consent page and among its clients."""

ACCESS_TOKEN_LIFETIME = 7 * 24 * 3600
"""Seconds an access token of cozy-stack lasts, which its token endpoint does not say."""


class InstanceRefused(Exception):
    """The instance refused a code or a refresh token, such as once its owner removed the
    broker from it."""


class InstanceUnavailable(Exception):
    """The instance gave no usable answer, so the same request may work later."""


@dataclass(frozen=True)
class Client:
    """The broker's OAuth client on one instance."""

    client_id: str
    client_secret: str
    registration_access_token: str
    """What lets the broker remove the client from the instance."""


def _json(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


class CozyStack:
    def __init__(
        self,
        http: httpx.AsyncClient,
        clock: Callable[[], float],
        *,
        redirect_uri: str,
        client_uri: str,
    ) -> None:
        self._http = http
        self._clock = clock
        self._redirect_uri = redirect_uri
        self._client_uri = client_uri

    async def register(self, instance: str) -> Client:
        """A new client of the broker on the instance, by dynamic client registration."""
        try:
            response = await self._http.post(
                f"https://{instance}/auth/register",
                json={
                    "redirect_uris": [self._redirect_uri],
                    "client_name": CLIENT_NAME,
                    "client_kind": "web",
                    "client_uri": self._client_uri,
                    "software_id": "github.com/linagora/twake-space-token-broker",
                },
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as error:
            raise InstanceUnavailable(f"no answer ({type(error).__name__})") from error
        body = _json(response)
        if response.status_code != 201:
            raise InstanceUnavailable(f"HTTP {response.status_code} {body.get('error', '')}")
        try:
            return Client(
                client_id=body["client_id"],
                client_secret=body["client_secret"],
                registration_access_token=body["registration_access_token"],
            )
        except KeyError as error:
            raise InstanceUnavailable("an answer without the client") from error

    def authorize_url(self, instance: str, client: Client, *, state: str, verifier: str) -> str:
        """Where the instance's owner grants the client access to their files, with PKCE."""
        query = urlencode(
            {
                "response_type": "code",
                "client_id": client.client_id,
                "redirect_uri": self._redirect_uri,
                "scope": SCOPE,
                "state": state,
                "code_challenge": pkce.challenge(verifier),
                "code_challenge_method": "S256",
            }
        )
        return f"https://{instance}/auth/authorize?{query}"

    async def redeem(self, instance: str, client: Client, code: str, verifier: str) -> Tokens:
        """Exchanges the code the instance sent its owner back with for the client's tokens."""
        tokens = await self._token(
            instance,
            client,
            {"grant_type": "authorization_code", "code": code, "code_verifier": verifier},
        )
        if tokens.refresh_token is None:
            raise InstanceUnavailable("an answer without a refresh token")
        return tokens

    async def _token(self, instance: str, client: Client, form: dict[str, str]) -> Tokens:
        """Tokens from the instance's token endpoint, whose every refusal is a 400."""
        requested_at = self._clock()
        try:
            response = await self._http.post(
                f"https://{instance}/auth/access_token",
                data={**form, "client_id": client.client_id, "client_secret": client.client_secret},
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as error:
            raise InstanceUnavailable(f"no answer ({type(error).__name__})") from error
        body = _json(response)
        if response.status_code == 400:
            raise InstanceRefused(body.get("error", ""))
        if response.status_code != 200:
            raise InstanceUnavailable(f"HTTP {response.status_code} {body.get('error', '')}")
        try:
            return Tokens(
                access_token=body["access_token"],
                requested_at=requested_at,
                expires_at=requested_at + int(body.get("expires_in", ACCESS_TOKEN_LIFETIME)),
                refresh_token=body.get("refresh_token"),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise InstanceUnavailable("an answer without tokens") from error
