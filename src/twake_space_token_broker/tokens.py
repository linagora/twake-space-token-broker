"""Access tokens for the users who consented, which APISIX hands to the contracts."""

from collections.abc import Callable
from dataclasses import dataclass

from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.lemonldap import GrantRefused, LemonLDAP

REFRESH_MARGIN = 300
"""Seconds before its expiry when an access token is no longer handed out, but refreshed."""


class DelegationMissing(Exception):
    """The user never consented to their agent acting for them."""


class DelegationExpired(Exception):
    """The user consented, but LemonLDAP no longer honours their consent."""


@dataclass(frozen=True)
class _Cached:
    access_token: str
    expires_at: float


class AccessTokens:
    def __init__(
        self, delegations: Delegations, lemonldap: LemonLDAP, clock: Callable[[], float]
    ) -> None:
        self._delegations = delegations
        self._lemonldap = lemonldap
        self._clock = clock
        self._cache: dict[str, _Cached] = {}

    async def of(self, user: str) -> str:
        """A fresh access token of the user, for the user's agent."""
        cached = self._cache.get(user)
        if cached is not None and self._clock() < cached.expires_at - REFRESH_MARGIN:
            return cached.access_token
        refresh_token = await self._delegations.refresh_token_of(user)
        if refresh_token is None:
            raise DelegationMissing()
        requested_at = self._clock()
        try:
            tokens = await self._lemonldap.refresh(refresh_token)
        except GrantRefused as refused:
            raise DelegationExpired() from refused
        self._cache[user] = _Cached(tokens.access_token, requested_at + tokens.expires_in)
        return tokens.access_token
