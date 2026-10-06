"""A fake cozy-stack serving the users' Drive instances, with the OAuth endpoints the broker uses.

It answers as cozy-stack 1.6.63 does (web/auth/oauth.go, model/oauth/client.go): errors of the
token endpoint are a 400 with a sentence in `error`, and its answers say nothing of when the
access token expires.
"""

import base64
import hashlib
import itertools
import json
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import parse_qsl

import httpx

Outage = Literal["error page", "unreachable"]


@dataclass(frozen=True)
class _Client:
    client_id: str
    client_secret: str
    registration_access_token: str
    metadata: dict[str, object]
    """What the broker registered: its name, redirect URIs, software and kind."""


@dataclass(frozen=True)
class _Code:
    client_id: str
    challenge: str
    scope: str


@dataclass
class _Instance:
    clients: dict[str, _Client] = field(default_factory=dict)


def _error(status: int, error: str) -> httpx.Response:
    return httpx.Response(status, json={"error": error})


class FakeCozyStack:
    def __init__(self) -> None:
        self._serial = itertools.count(1)
        self._instances: dict[str, _Instance] = {}
        self._codes: dict[str, _Code] = {}
        self._refresh_tokens: dict[str, tuple[str, str, str]] = {}
        """Each refresh token's instance, client and scope."""
        self._access_tokens: dict[str, tuple[str, str]] = {}
        """Each access token's instance and scope."""
        self.outage: Outage | None = None
        self.rotates_refresh_tokens = False
        """cozy-stack does once an instance moved to another domain."""
        self.transport = httpx.MockTransport(self._handle)

    def create_instance(self, host: str) -> None:
        self._instances[host] = _Instance()

    def authorize(self, authorize_url: str) -> str:
        """The owner accepts on their instance: it sends their browser back with a code."""
        url = httpx.URL(authorize_url)
        client, redirect_uri = self._check_authorize(url)
        code = f"drive-code-{next(self._serial)}"
        self._codes[code] = _Code(
            client.client_id, url.params["code_challenge"], url.params["scope"]
        )
        back = redirect_uri.copy_merge_params(
            {"state": url.params["state"], "access_code": code, "code": code}
        )
        # cozy-stack ends the location with "#", so that no fragment of the request survives
        return f"{back}#"

    def refuse(self, authorize_url: str) -> str:
        """The owner declines on their instance, whose page links back with no state."""
        _, redirect_uri = self._check_authorize(httpx.URL(authorize_url))
        return str(redirect_uri.copy_merge_params({"error": "access_denied"}))

    def access_of(self, access_token: str) -> tuple[str, str] | None:
        """The instance an access token was issued by, and its scope."""
        return self._access_tokens.get(access_token)

    def credentials_on(self, host: str) -> list[str]:
        """The secrets the instance gave out: client secrets, registration and refresh tokens."""
        clients = self._instances[host].clients.values()
        return [
            *(client.client_secret for client in clients),
            *(client.registration_access_token for client in clients),
            *(token for token, (issuer, _, _) in self._refresh_tokens.items() if issuer == host),
        ]

    def clients_on(self, host: str) -> list[dict[str, object]]:
        """What the clients registered on the instance said of themselves."""
        return [client.metadata for client in self._instances[host].clients.values()]

    def remove_clients(self, host: str) -> None:
        """The owner removes the broker from the applications connected to their instance."""
        self._instances[host].clients.clear()

    def _check_authorize(self, url: httpx.URL) -> tuple[_Client, httpx.URL]:
        """The client and redirect URI of an authorization request, checked as cozy-stack does."""
        assert url.scheme == "https"
        assert url.path == "/auth/authorize"
        instance = self._instances[url.host]
        assert url.params["response_type"] == "code"
        assert url.params["code_challenge_method"] == "S256"
        assert url.params["code_challenge"]
        assert url.params["state"]
        assert url.params["scope"]
        client = instance.clients[url.params["client_id"]]
        redirect_uris = client.metadata["redirect_uris"]
        assert isinstance(redirect_uris, list)
        assert url.params["redirect_uri"] in redirect_uris
        return client, httpx.URL(url.params["redirect_uri"])

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if self.outage == "unreachable":
            raise httpx.ConnectError("Connection refused", request=request)
        instance = self._instances.get(request.url.host)
        if instance is None:
            raise httpx.ConnectError("Name or service not known", request=request)
        if self.outage == "error page":
            return httpx.Response(503, html="<h1>Service Unavailable</h1>")
        assert request.url.scheme == "https"
        path = request.url.path
        if request.method == "POST" and path == "/auth/register":
            return self._register(instance, request)
        if request.method == "DELETE" and path.startswith("/auth/register/"):
            return self._unregister(instance, path.removeprefix("/auth/register/"), request)
        if request.method == "POST" and path == "/auth/access_token":
            return self._access_token(request.url.host, instance, request)
        return httpx.Response(404, json={"error": "Not Found"})

    def _register(self, instance: _Instance, request: httpx.Request) -> httpx.Response:
        assert request.headers["content-type"] == "application/json"
        metadata = json.loads(request.content)
        redirect_uris = metadata.get("redirect_uris")
        if not redirect_uris or any(httpx.URL(uri).fragment for uri in redirect_uris):
            return _error(400, "invalid_redirect_uri")
        if not metadata.get("client_name") or not metadata.get("software_id"):
            return _error(400, "invalid_client_metadata")
        client = _Client(
            client_id=f"client-{next(self._serial)}",
            client_secret=f"client-secret-{next(self._serial)}",
            registration_access_token=f"registration-{next(self._serial)}",
            metadata=metadata,
        )
        instance.clients[client.client_id] = client
        return httpx.Response(
            201,
            json={
                **metadata,
                "client_id": client.client_id,
                "client_secret": client.client_secret,
                "client_secret_expires_at": 0,
                "registration_access_token": client.registration_access_token,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )

    def _unregister(
        self, instance: _Instance, client_id: str, request: httpx.Request
    ) -> httpx.Response:
        client = instance.clients.get(client_id)
        if client is None:
            # As cozy-stack does (deleteClient in web/auth/register.go)
            return httpx.Response(204)
        if request.headers.get("authorization") != f"Bearer {client.registration_access_token}":
            return httpx.Response(401, json={"error": "Unauthorized"})
        del instance.clients[client_id]
        return httpx.Response(204)

    def _access_token(
        self, host: str, instance: _Instance, request: httpx.Request
    ) -> httpx.Response:
        form = dict(parse_qsl(request.content.decode()))
        client = instance.clients.get(form.get("client_id", ""))
        if client is None:
            return _error(400, "the client must be registered")
        if form.get("client_secret") != client.client_secret:
            return _error(400, "invalid client_secret")
        if form.get("grant_type") == "authorization_code":
            code = self._codes.pop(form.get("code", ""), None)
            if code is None or code.client_id != client.client_id:
                return _error(400, "invalid code")
            verifier = form.get("code_verifier", "")
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            if challenge.rstrip(b"=").decode() != code.challenge:
                return _error(400, "invalid code_verifier")
            refresh_token = f"drive-refresh-{next(self._serial)}"
            self._refresh_tokens[refresh_token] = (host, client.client_id, code.scope)
            return httpx.Response(
                200, json={**self._access(host, code.scope), "refresh_token": refresh_token}
            )
        if form.get("grant_type") == "refresh_token":
            presented = form.get("refresh_token", "")
            issued = self._refresh_tokens.get(presented)
            if issued is None or issued[:2] != (host, client.client_id):
                return _error(400, "invalid refresh token")
            scope = issued[2]
            if not self.rotates_refresh_tokens:
                return httpx.Response(200, json=self._access(host, scope))
            del self._refresh_tokens[presented]
            rotated = f"drive-refresh-{next(self._serial)}"
            self._refresh_tokens[rotated] = issued
            return httpx.Response(200, json={**self._access(host, scope), "refresh_token": rotated})
        return _error(400, "invalid grant type")

    def _access(self, host: str, scope: str) -> dict[str, str]:
        access_token = f"drive-access-{next(self._serial)}"
        self._access_tokens[access_token] = (host, scope)
        return {"token_type": "bearer", "scope": scope, "access_token": access_token}
