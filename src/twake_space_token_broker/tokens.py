"""Access tokens for the users who consented, which APISIX hands to the contracts."""

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.keys import Undecryptable
from twake_space_token_broker.lemonldap import GrantRefused, LemonLDAP, SignedIn, Tokens

logger = logging.getLogger(__name__)

REFRESH_MARGIN = 300
"""Seconds before its expiry when an access token is no longer handed out, but refreshed."""


def reusable_until(tokens: Tokens, reuse_seconds: int) -> float:
    """When to stop handing out an access token and ask for a new one, in seconds since the epoch.

    The token lasts hours, but only a refresh tells whether its delegation is still honoured:
    counted from the request, so that a slow answer cannot stretch it, reuse_seconds bounds how
    long a revoked delegation still gets tokens.
    """
    return min(tokens.requested_at + reuse_seconds, tokens.expires_at - REFRESH_MARGIN)


class DelegationMissing(Exception):
    """The user never consented to their agent acting for them."""


class DelegationExpired(Exception):
    """The user consented, but LemonLDAP no longer honours their consent."""


@dataclass(frozen=True)
class _Cached:
    access_token: str
    reusable_until: float
    """When to stop handing out the token and ask LemonLDAP again, in seconds since the epoch."""


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
        self._clock = clock
        self._reuse_seconds = reuse_seconds
        self._cache: dict[str, _Cached] = {}
        self._refreshing: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def consented(self, signed_in: SignedIn) -> None:
        """Keeps the user's new delegation in place of any earlier one, with its access token."""
        await self._delegations.save(signed_in.user, signed_in.refresh_token)
        self._keep(signed_in.user, signed_in.tokens)

    async def of(self, user: str) -> str:
        """A fresh access token of the user, for the user's agent."""
        # One refresh at a time per user: a rotated refresh token would void the others
        async with self._refreshing[user]:
            return self._fresh(user) or await self._refresh(user)

    def _fresh(self, user: str) -> str | None:
        cached = self._cache.get(user)
        if cached is not None and self._clock() < cached.reusable_until:
            return cached.access_token
        return None

    def _keep(self, user: str, tokens: Tokens) -> None:
        """Keeps the user's access token, to hand out until LemonLDAP must be asked again."""
        self._cache[user] = _Cached(
            access_token=tokens.access_token,
            reusable_until=reusable_until(tokens, self._reuse_seconds),
        )

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
            await self._delegations.save(user, tokens.refresh_token)
        self._keep(user, tokens)
        return tokens.access_token
