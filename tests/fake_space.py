"""A fake Twake Space API, serving the routes the broker calls with the owner's API token.

It answers as Space 0.1.18 does (modules/auth/routes.ts, spaces/routes.ts, spaces/writes.ts,
feed/routes.ts, tokens/routes.ts): a route checks the token's scope before anything else, and
answers 403 insufficient_scope without it. Past that check, a route checks its parameters, then its
body, then the space, so that a request on a space that does not exist answers 400 or 404 before
anything is written.

An account's token acts in the spaces where the account is a member, with the account's role in
each. An organization token acts in every space of the organization, with its own role.
"""

import json
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Literal, get_args

import httpx

Outage = Literal["error page", "unreachable"]

Role = Literal["viewer", "editor", "admin"]

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")

SPACE = r"/spaces/(?P<id>[^/]+)"

ROUTES = (
    ("GET", re.compile(r"/spaces"), "space:read"),
    ("GET", re.compile(SPACE), "space:read"),
    ("GET", re.compile(rf"{SPACE}/feed"), "feed:read"),
    ("POST", re.compile(rf"{SPACE}/members"), "members:write"),
    ("PATCH", re.compile(SPACE), "space:write"),
    ("GET", re.compile(r"/tokens"), "tokens:write"),
)
"""The routes the broker calls, with the scope each one needs."""

ROLES = get_args(Role)

SOMEONE = "someone@example.test"
"""The account that creates a token when the test names none: a member of no space."""


@dataclass(frozen=True)
class _AccountToken:
    scopes: frozenset[str]
    account: str
    """The email of the account the token acts for."""


@dataclass(frozen=True)
class _OrganizationToken:
    scopes: frozenset[str]
    role: Role
    """The role the token acts with in every space of the organization."""


_Token = _AccountToken | _OrganizationToken


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


def _username(email: str) -> str:
    return email.partition("@")[0]


class FakeSpace:
    def __init__(self, host: str) -> None:
        self._host = host
        self._tokens: dict[str, _Token] = {}
        self._spaces: dict[str, dict[str, Role]] = {}
        """The spaces of the organization, with the email and the role of each member."""
        self.outage: Outage | None = None
        self.failing_spaces: set[str] = set()
        """The spaces whose page Space fails to show, answering an error page."""
        self.requests: list[httpx.Request] = []
        self.writes: list[httpx.Request] = []
        """The requests Space would have carried out on a space that exists."""
        self.transport = httpx.MockTransport(self._handle)

    def create_space(self, members: dict[str, Role]) -> str:
        """A space of the organization, with the email and the role of each member: its id."""
        space = str(uuid.uuid4())
        self._spaces[space] = dict(members)
        return space

    def create_token(self, *scopes: str, account: str = SOMEONE) -> str:
        """The account creates an API token with the scopes given, as Space's page does."""
        return self._create(_AccountToken(frozenset(scopes), account))

    def create_organization_token(self, *scopes: str, role: Role) -> str:
        """An admin of the organization creates a token of the organization, with the scopes and
        the role given."""
        return self._create(_OrganizationToken(frozenset(scopes), role))

    def _create(self, token: _Token) -> str:
        secret = f"tws_{secrets.token_urlsafe(32)}"
        self._tokens[secret] = token
        return secret

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
        scheme, _, secret = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not secret:
            return _error(401, "unauthorized", challenge="Bearer")
        token = self._tokens.get(secret)
        if token is None:
            return _error(401, "unauthorized", challenge='Bearer error="invalid_token"')
        for method, path, scope in ROUTES:
            route = path.fullmatch(request.url.path)
            if route is None or request.method != method:
                continue
            if scope not in token.scopes:
                return _error(
                    403,
                    "insufficient_scope",
                    challenge=f'Bearer error="insufficient_scope", scope="{scope}"',
                )
            return self._route(token, scope, route.groupdict().get("id"), request)
        return _error(404, "not_found")

    def _route(
        self,
        token: _Token,
        scope: str,
        space: str | None,
        request: httpx.Request,
    ) -> httpx.Response:
        if scope == "tokens:write":
            return self._tokens_of(token)
        if scope == "space:read":
            return self._spaces_of(token) if space is None else self._space(token, space)
        if scope == "feed:read":
            # The broker reads no feed: it probes that of a space that does not exist
            return _error(404, "not_found")
        if space is None or not UUID.fullmatch(space):
            return _error(400, "invalid_request")
        checks = _adds_members if scope == "members:write" else _renames
        if not checks(_body(request)):
            return _error(400, "invalid_request")
        self.writes.append(request)
        return _error(404, "not_found")

    def _reached(self, token: _Token) -> dict[str, Role]:
        """The spaces the token acts in, each with the role it acts with there."""
        if isinstance(token, _OrganizationToken):
            return dict.fromkeys(self._spaces, token.role)
        return {
            space: members[token.account]
            for space, members in self._spaces.items()
            if token.account in members
        }

    def _spaces_of(self, token: _Token) -> httpx.Response:
        """GET /spaces, which names the members of each space without their emails."""
        spaces = [
            {
                "id": space,
                "role": role,
                "members": [{"username": _username(email)} for email in self._spaces[space]],
            }
            for space, role in self._reached(token).items()
        ]
        return httpx.Response(200, json={"spaces": spaces})

    def _space(self, token: _Token, space: str) -> httpx.Response:
        """GET /spaces/:id, which names the members of the space with their emails and roles."""
        role = self._reached(token).get(space)
        if role is None:
            return _error(404, "not_found")
        if space in self.failing_spaces:
            return httpx.Response(503, html="<h1>Service Unavailable</h1>")
        members = [
            {"username": _username(email), "email": email, "role": member}
            for email, member in self._spaces[space].items()
        ]
        return httpx.Response(
            200, json={"id": space, "role": role, "members": members, "groups": []}
        )

    def _tokens_of(self, token: _Token) -> httpx.Response:
        """GET /tokens, which lists the tokens of the caller's account, and which an organization
        token is refused past the check of its scope."""
        if isinstance(token, _OrganizationToken):
            return httpx.Response(
                403, json={"error": "forbidden", "message": "not an account token"}
            )
        tokens = [
            {"scopes": sorted(other.scopes)}
            for other in self._tokens.values()
            if isinstance(other, _AccountToken) and other.account == token.account
        ]
        return httpx.Response(200, json={"tokens": tokens})
