"""Access tokens for the users who consented, which APISIX hands to the contracts."""

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.keys import Undecryptable
from twake_space_token_broker.lemonldap import GrantRefused, LemonLDAP, SignedIn
from twake_space_token_broker.oauth import Tokens

logger = logging.getLogger(__name__)

REFRESH_MARGIN = 300
"""Seconds before its expiry when an access token is no longer handed out, but refreshed."""


@dataclass(frozen=True)
class _Kept[T]:
    value: T
    reusable_until: float
    """When to stop handing out the value and ask for a new token, in seconds since the epoch."""


class TokenCache[T]:
    """What the broker hands out of each user's latest access token, until it must refresh it."""

    def __init__(self, clock: Callable[[], float], *, reuse_seconds: int) -> None:
        self._clock = clock
        self._reuse_seconds = reuse_seconds
        self._kept: dict[str, _Kept[T]] = {}

    def fresh(self, user: str) -> T | None:
        kept = self._kept.get(user)
        if kept is not None and self._clock() < kept.reusable_until:
            return kept.value
        return None

    def keep(self, user: str, value: T, tokens: Tokens) -> None:
        """Keeps what to hand out of the user's new tokens, until they must be refreshed."""
        self._kept[user] = _Kept(
            value,
            # The token lasts hours, but only a refresh tells whether its delegation is still
            # honoured: counted from the request, so that a slow answer cannot stretch it,
            # reuse_seconds bounds how long a revoked delegation still gets tokens
            min(tokens.requested_at + self._reuse_seconds, tokens.expires_at - REFRESH_MARGIN),
        )

    def drop(self, user: str) -> None:
        self._kept.pop(user, None)


class DelegationMissing(Exception):
    """The user never consented to their agent acting for them."""


class DelegationExpired(Exception):
    """The user consented, but LemonLDAP no longer honours their consent."""


class AccessTokens:
    def __init__(
        self,
        delegations: Delegations,
        lemonldap: LemonLDAP,
        clock: Callable[[], float],
        *,
        reuse_seconds: int,
    ) -> None:
        self._delegations = delegations
        self._lemonldap = lemonldap
        self._cache = TokenCache[str](clock, reuse_seconds=reuse_seconds)
        self._refreshing: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def consented(self, signed_in: SignedIn) -> None:
        """Keeps the user's new delegation in place of any earlier one, with its access token."""
        await self._delegations.save(
            signed_in.user,
            signed_in.refresh_token,
            # LemonLDAP starts the offline session as it answers: from the request, the
            # delegation never seems to last longer than it does
            consented_at=datetime.fromtimestamp(signed_in.tokens.requested_at, UTC),
        )
        self._cache.keep(signed_in.user, signed_in.tokens.access_token, signed_in.tokens)

    async def consented_at(self, user: str) -> datetime | None:
        """When the user consented, unless they never did or revoked their delegation since."""
        return await self._delegations.consented_at(user)

    async def revoke(self, user: str) -> None:
        """Revokes the user's delegation, whose agent gets no token from then on."""
        # Under the user's lock, so that a refresh in progress cannot put its token back
        async with self._refreshing[user]:
            await self._delegations.revoke(user)
            self._cache.drop(user)

    async def of(self, user: str) -> str:
        """A fresh access token of the user, for the user's agent."""
        # One refresh at a time per user: a rotated refresh token would void the others
        async with self._refreshing[user]:
            return self._cache.fresh(user) or await self._refresh(user)

    async def _refresh(self, user: str) -> str:
        try:
            refresh_token = await self._delegations.refresh_token_of(user)
        except Undecryptable as undecryptable:
            logger.warning("The delegation of %s does not decrypt with ENCRYPTION_KEY", user)
            raise DelegationExpired() from undecryptable
        if refresh_token is None:
            raise DelegationMissing()
        try:
            tokens = await self._lemonldap.refresh(refresh_token)
        except GrantRefused as refused:
            # LemonLDAP's error tells a deleted offline session (invalid_request) from a user
            # it no longer finds or cannot look up (invalid_grant)
            logger.warning("LemonLDAP refused the delegation of %s (%s)", user, refused)
            raise DelegationExpired() from refused
        if tokens.refresh_token is not None and tokens.refresh_token != refresh_token:
            await self._delegations.replace_refresh_token(user, tokens.refresh_token)
        self._cache.keep(user, tokens.access_token, tokens)
        return tokens.access_token
