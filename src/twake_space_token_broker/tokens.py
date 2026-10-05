"""Access tokens for the users who consented, which APISIX hands to the contracts."""

from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.lemonldap import LemonLDAP


class AccessTokens:
    def __init__(self, delegations: Delegations, lemonldap: LemonLDAP) -> None:
        self._delegations = delegations
        self._lemonldap = lemonldap

    async def of(self, user: str) -> str:
        """A fresh access token of the user, for the user's agent."""
        refresh_token = await self._delegations.refresh_token_of(user)
        assert refresh_token is not None
        tokens = await self._lemonldap.refresh(refresh_token)
        return tokens.access_token
