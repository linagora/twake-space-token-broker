"""Twake Space, where the users' agents act with an API token the users paste on the consent."""

import logging
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from twake_space_token_broker.delegations import Delegations, SpaceToken
from twake_space_token_broker.keys import Undecryptable
from twake_space_token_broker.tokens import DelegationMissing

logger = logging.getLogger(__name__)

TOKENS_PAGE = "/settings/api-tokens"
"""Space's page of API tokens, relative to where users open Space: it opens on their own tokens."""

TOKEN = re.compile(r"tws_[A-Za-z0-9_-]{1,256}")
"""An API token of Space: tws_, then base64url, as Space makes them."""

SCOPES = {
    "space:read": "Lire les espaces",
    "feed:read": "Lire les fils",
    "members:write": "Gérer les membres",
    "space:write": "Modifier les espaces",
}
"""The scopes the agent uses, each named as Space's list of API tokens names it."""

REQUIRED = frozenset({"space:read", "feed:read"})
"""The scopes the agent cannot do without: it reads the spaces, then their feeds."""

MANAGES_TOKENS = "tokens:write"
"""The scope that lets a token create other tokens, which no token the broker keeps may hold."""


class NotASpaceToken(Exception):
    """What the user pasted is no API token of Space."""


class SpaceRefused(Exception):
    """Space does not know the token: it was mistyped, revoked, or it expired."""


class SpaceUnavailable(Exception):
    """Space gave no answer the broker understands."""


class TooBroad(Exception):
    """The token may manage API tokens: were it to leak, it would create others."""


class ScopesMissing(Exception):
    """The token lacks a scope the agent cannot do without."""

    def __init__(self, held: frozenset[str]) -> None:
        super().__init__(f"The token holds {sorted(held)} only")
        self.held = held


class NotTheirs(Exception):
    """The token does not act for the user in every space it reaches: it is an organization
    token, or another account's."""


class SpaceTokenMissing(Exception):
    """The user has given their agent no Space token."""


@dataclass(frozen=True)
class KeptToken:
    """What the consent shows of the Space token a user pasted: never the token itself."""

    scopes: frozenset[str]
    """The scopes among SCOPES that Space showed the token to hold."""
    pasted_at: datetime


def _error(response: httpx.Response) -> object:
    """The error Space names in its answer, if any."""
    try:
        body = response.json()
    except ValueError:
        return None
    return body.get("error") if isinstance(body, dict) else None


class Space:
    """Twake Space's API, which the broker asks what a user's API token allows, and whom it acts
    for."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def scopes_of(self, token: str) -> frozenset[str]:
        """The scopes among SCOPES and MANAGES_TOKENS that the token holds, asked without changing
        anything.

        A route of Space checks its scope before anything else, and answers 403 insufficient_scope
        without it. Past that check, each probe stops on a space that does not exist, at the space
        or at a body that names nothing to change: a 404 or a 400. The list of tokens answers an
        account's token, and refuses an organization token with 403 forbidden.

        Raises SpaceRefused when Space does not know the token, and SpaceUnavailable when it gives
        no answer the broker understands.
        """
        nowhere = uuid.uuid4()
        probes: tuple[tuple[str, str, str, dict[str, object] | None], ...] = (
            ("space:read", "GET", "/spaces", None),
            ("feed:read", "GET", f"/spaces/{nowhere}/feed", None),
            ("members:write", "POST", f"/spaces/{nowhere}/members", {}),
            ("space:write", "PATCH", f"/spaces/{nowhere}", {}),
            (MANAGES_TOKENS, "GET", "/tokens", None),
        )
        held = set()
        for scope, method, path, body in probes:
            if await self._holds(token, method, path, body):
                held.add(scope)
        return frozenset(held)

    async def acts_for(self, token: str, user: str) -> bool:
        """Whether the token acts for the user in every space it reaches: whether they are a member
        of each, under their email whatever its case, with the role Space gives the token there.

        Space names no one a token acts for. A token of the user's account acts in their spaces,
        with their role in each. An organization token acts in every space of the organization
        with a role of its own, and another account's token in that account's spaces with that
        account's role: either fails in a space where the user is not a member with that role. A
        token that reaches no space passes, as nothing tells whose it is then.

        Raises SpaceRefused and SpaceUnavailable as scopes_of does.
        """
        listed = await self._read(token, "/spaces")
        try:
            reached = [(uuid.UUID(space["id"]), space["role"]) for space in listed.json()["spaces"]]
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            raise SpaceUnavailable("GET /spaces answered no list of spaces") from error
        for space, role in reached:
            shown = await self._read(token, f"/spaces/{space}")
            try:
                members = [
                    (member["email"].casefold(), member["role"])
                    for member in shown.json()["members"]
                ]
            except (AttributeError, KeyError, TypeError, ValueError) as error:
                raise SpaceUnavailable(f"GET /spaces/{space} answered no members") from error
            if (user.casefold(), role) not in members:
                return False
        return True

    async def _holds(self, token: str, method: str, path: str, body: object) -> bool:
        """Whether Space let the request past its check of the route's scope."""
        response = await self._request(token, method, path, body)
        if response.status_code == 401:
            raise SpaceRefused()
        error = _error(response)
        if response.status_code == 403 and error == "insufficient_scope":
            return False
        if response.status_code in (200, 400, 404) or (
            response.status_code == 403 and error == "forbidden"
        ):
            return True
        raise SpaceUnavailable(f"{method} {path} answered {response.status_code}")

    async def _read(self, token: str, path: str) -> httpx.Response:
        """Space's answer to a GET with the token, which it must let through."""
        response = await self._request(token, "GET", path)
        if response.status_code == 401:
            raise SpaceRefused()
        if response.status_code != 200:
            raise SpaceUnavailable(f"GET {path} answered {response.status_code}")
        return response

    async def _request(
        self, token: str, method: str, path: str, body: object = None
    ) -> httpx.Response:
        try:
            return await self._http.request(
                method,
                path,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                json=body,
            )
        except httpx.HTTPError as error:
            raise SpaceUnavailable(f"{method} {path}: {error!r}") from error


class SpaceTokens:
    """The API tokens the users paste on the consent, for their agents to reach Twake Space."""

    def __init__(
        self,
        delegations: Delegations,
        space: Space,
        clock: Callable[[], float],
        *,
        tokens_page: str,
    ) -> None:
        self._delegations = delegations
        self._space = space
        self._clock = clock
        self.tokens_page = tokens_page
        """Where users create the API tokens they paste."""

    async def paste(self, user: str, pasted: str) -> frozenset[str]:
        """Checks with Space the token the user pasted, then keeps it for their agent, in place of
        any earlier one: the scopes it holds among SCOPES.

        Raises NotASpaceToken, SpaceRefused, TooBroad, ScopesMissing or NotTheirs when the token
        will not do, SpaceUnavailable when Space cannot tell, and DelegationMissing when the user's
        delegation went meanwhile: nothing is kept then, and any earlier token stays.
        """
        token = pasted.strip()
        if not TOKEN.fullmatch(token):
            raise NotASpaceToken()
        held = await self._space.scopes_of(token)
        if MANAGES_TOKENS in held:
            raise TooBroad()
        if not held >= REQUIRED:
            raise ScopesMissing(held)
        if not await self._space.acts_for(token, user):
            raise NotTheirs()
        pasted_at = datetime.fromtimestamp(self._clock(), UTC)
        if not await self._delegations.save_space_token(
            user, token, scopes=sorted(held), pasted_at=pasted_at
        ):
            raise DelegationMissing()
        return held

    async def kept(self, user: str) -> KeptToken | None:
        """What the user's Space token allows and when they pasted it, if they gave their agent
        one."""
        pasted = await self._pasted(user)
        return None if pasted is None else KeptToken(pasted.scopes, pasted.pasted_at)

    async def remove(self, user: str) -> None:
        """Forgets the Space token the user pasted: their agent no longer acts in Twake Space."""
        await self._delegations.forget_space_token(user)

    async def of(self, user: str) -> str:
        """The Space token the user pasted, for their agent."""
        pasted = await self._pasted(user)
        if pasted is None:
            raise SpaceTokenMissing()
        return pasted.token

    async def _pasted(self, user: str) -> SpaceToken | None:
        """The Space token the user pasted, unless it no longer decrypts, which counts as none."""
        try:
            return await self._delegations.space_token_of(user)
        except Undecryptable:
            logger.warning("The Space token of %s does not decrypt with ENCRYPTION_KEY", user)
            return None
