"""Twake Space, where the users' agents act with an API token the users paste on the consent."""

import logging
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

import httpx

from twake_space_token_broker.delegations import Delegations
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


class NotASpaceToken(Exception):
    """What the user pasted is no API token of Space."""


class SpaceRefused(Exception):
    """Space does not know the token: it was mistyped, revoked, or it expired."""


class SpaceUnavailable(Exception):
    """Space gave no answer the broker understands."""


class ScopesMissing(Exception):
    """The token lacks a scope the agent cannot do without."""

    def __init__(self, held: frozenset[str]) -> None:
        super().__init__(f"The token holds {sorted(held)} only")
        self.held = held


class SpaceTokenMissing(Exception):
    """The user has given their agent no Space token."""


def _error(response: httpx.Response) -> object:
    """The error Space names in its answer, if any."""
    try:
        body = response.json()
    except ValueError:
        return None
    return body.get("error") if isinstance(body, dict) else None


class Space:
    """Twake Space's API, which the broker asks what a user's API token allows."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def scopes_of(self, token: str) -> frozenset[str]:
        """The scopes among SCOPES that the token holds, asked without changing anything.

        A route of Space checks its scope before anything else, and answers 403 insufficient_scope
        without it. Past that check, each probe stops on a space that does not exist, at the space
        or at a body that names nothing to change: a 404 or a 400.

        Raises SpaceRefused when Space does not know the token, and SpaceUnavailable when it gives
        no answer the broker understands.
        """
        nowhere = uuid.uuid4()
        probes: tuple[tuple[str, str, str, dict[str, object] | None], ...] = (
            ("space:read", "GET", "/spaces", None),
            ("feed:read", "GET", f"/spaces/{nowhere}/feed", None),
            ("members:write", "POST", f"/spaces/{nowhere}/members", {}),
            ("space:write", "PATCH", f"/spaces/{nowhere}", {}),
        )
        held = set()
        for scope, method, path, body in probes:
            if await self._holds(token, method, path, body):
                held.add(scope)
        return frozenset(held)

    async def _holds(self, token: str, method: str, path: str, body: object) -> bool:
        """Whether Space let the request past its check of the route's scope."""
        try:
            response = await self._http.request(
                method,
                path,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                json=body,
            )
        except httpx.HTTPError as error:
            raise SpaceUnavailable(f"{method} {path}: {error!r}") from error
        if response.status_code == 401:
            raise SpaceRefused()
        if response.status_code == 403 and _error(response) == "insufficient_scope":
            return False
        if response.status_code in (200, 400, 404):
            return True
        raise SpaceUnavailable(f"{method} {path} answered {response.status_code}")


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

        Raises NotASpaceToken, SpaceRefused or ScopesMissing when the token will not do,
        SpaceUnavailable when Space cannot tell, and DelegationMissing when the user's delegation
        went meanwhile: nothing is kept then.
        """
        token = pasted.strip()
        if not TOKEN.fullmatch(token):
            raise NotASpaceToken()
        held = await self._space.scopes_of(token)
        if not held >= REQUIRED:
            raise ScopesMissing(held)
        pasted_at = datetime.fromtimestamp(self._clock(), UTC)
        if not await self._delegations.save_space_token(
            user, token, scopes=sorted(held), pasted_at=pasted_at
        ):
            raise DelegationMissing()
        return held

    async def of(self, user: str) -> str:
        """The Space token the user pasted, for their agent."""
        try:
            token = await self._delegations.space_token_of(user)
        except Undecryptable as undecryptable:
            logger.warning("The Space token of %s does not decrypt with ENCRYPTION_KEY", user)
            raise SpaceTokenMissing() from undecryptable
        if token is None:
            raise SpaceTokenMissing()
        return token
