"""A fake Twake Space API, serving the routes the broker probes with the owner's API token.

It answers as Space 0.1.18 does (modules/auth/routes.ts, spaces/routes.ts, spaces/writes.ts,
feed/routes.ts): a route checks the token's scope before anything else, and answers 403
insufficient_scope without it. Past that check, a route checks its parameters, then its body, then
the space, so that a request on a space that does not exist answers 400 or 404 before anything is
written.
"""

import json
import re
import secrets
from typing import Literal

import httpx

Outage = Literal["error page", "unreachable"]

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")

SPACE = r"/spaces/(?P<id>[^/]+)"

ROUTES = (
    ("GET", re.compile(r"/spaces"), "space:read"),
    ("GET", re.compile(rf"{SPACE}/feed"), "feed:read"),
    ("POST", re.compile(rf"{SPACE}/members"), "members:write"),
    ("PATCH", re.compile(SPACE), "space:write"),
)
"""The routes the broker calls, with the scope each one needs."""

ROLES = ("viewer", "editor", "admin")


def _error(status: int, error: str, *, challenge: str | None = None) -> httpx.Response:
    headers = {"www-authenticate": challenge} if challenge else {}
    return httpx.Response(status, json={"error": error}, headers=headers)


def _body(request: httpx.Request) -> object:
    return json.loads(request.content) if request.content else None


def _adds_members(body: object) -> bool:
    """Whether the body of POST /spaces/:id/members passes Space's checks."""
    if not isinstance(body, dict):
        return False
    usernames = body.get("usernames")
    return (
        isinstance(usernames, list)
        and 1 <= len(usernames) <= 100
        and all(isinstance(username, str) and username for username in usernames)
        and body.get("role") in ROLES
    )


def _renames(body: object) -> bool:
    """Whether the body of PATCH /spaces/:id passes Space's checks: a name or apps."""
    return isinstance(body, dict) and ("name" in body or "apps" in body)


class FakeSpace:
    def __init__(self, host: str) -> None:
        self._host = host
        self._tokens: dict[str, frozenset[str]] = {}
        self.outage: Outage | None = None
        self.requests: list[httpx.Request] = []
        self.writes: list[httpx.Request] = []
        """The requests Space would have carried out on a space that exists."""
        self.transport = httpx.MockTransport(self._handle)

    def create_token(self, *scopes: str) -> str:
        """The owner creates an API token with the scopes given, as Space's page does."""
        token = f"tws_{secrets.token_urlsafe(32)}"
        self._tokens[token] = frozenset(scopes)
        return token

    def revoke(self, token: str) -> None:
        del self._tokens[token]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.outage == "unreachable":
            raise httpx.ConnectError("Connection refused", request=request)
        if request.url.host != self._host:
            raise httpx.ConnectError("Name or service not known", request=request)
        if self.outage == "error page":
            return httpx.Response(503, html="<h1>Service Unavailable</h1>")
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            return _error(401, "unauthorized", challenge="Bearer")
        scopes = self._tokens.get(token)
        if scopes is None:
            return _error(401, "unauthorized", challenge='Bearer error="invalid_token"')
        for method, path, scope in ROUTES:
            route = path.fullmatch(request.url.path)
            if route is None or request.method != method:
                continue
            if scope not in scopes:
                return _error(
                    403,
                    "insufficient_scope",
                    challenge=f'Bearer error="insufficient_scope", scope="{scope}"',
                )
            return self._route(scope, route.groupdict().get("id"), request)
        return _error(404, "not_found")

    def _route(self, scope: str, space: str | None, request: httpx.Request) -> httpx.Response:
        if scope == "space:read":
            return httpx.Response(200, json={"spaces": []})
        if scope == "feed:read":
            # The fake knows no space: any id answers 404, as one the caller is not in
            return _error(404, "not_found")
        if space is None or not UUID.fullmatch(space):
            return _error(400, "invalid_request")
        checks = _adds_members if scope == "members:write" else _renames
        if not checks(_body(request)):
            return _error(400, "invalid_request")
        self.writes.append(request)
        return _error(404, "not_found")
