"""Access tokens for the users who consented, which APISIX hands to the contracts."""

from collections.abc import Callable

from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.lemonldap import GrantRefused, LemonLDAP, SignedIn, Tokens

REFRESH_MARGIN = 300
"""Seconds before its expiry when an access token is no longer handed out, but refreshed."""


class DelegationMissing(Exception):
    """The user never consented to their agent acting for them."""


class DelegationExpired(Exception):
    """The user consented, but LemonLDAP no longer honours their consent."""


class AccessTokens:
    def __init__(
        self, delegations: Delegations, lemonldap: LemonLDAP, clock: Callable[[], float]
    ) -> None:
        self._delegations = delegations
        self._lemonldap = lemonldap
        self._clock = clock
        self._cache: dict[str, Tokens] = {}

    async def consented(self, signed_in: SignedIn) -> None:
        """Keeps the user's new delegation in place of any earlier one, with its access token."""
        assert signed_in.tokens.refresh_token is not None
        await self._delegations.save(signed_in.user, signed_in.tokens.refresh_token)
        self._cache[signed_in.user] = signed_in.tokens

    async def of(self, user: str) -> str:
        """A fresh access token of the user, for the user's agent."""
        cached = self._cache.get(user)
        if cached is not None and self._clock() < cached.expires_at - REFRESH_MARGIN:
            return cached.access_token
        refresh_token = await self._delegations.refresh_token_of(user)
        if refresh_token is None:
            raise DelegationMissing()
        try:
            tokens = await self._lemonldap.refresh(refresh_token)
        except GrantRefused as refused:
            raise DelegationExpired() from refused
        if tokens.refresh_token is not None and tokens.refresh_token != refresh_token:
            await self._delegations.save(user, tokens.refresh_token)
        self._cache[user] = tokens
        return tokens.access_token
