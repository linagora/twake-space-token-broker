"""The revocation of a user's delegation, Drive included."""

from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.drive import DriveTokens
from twake_space_token_broker.tokens import AccessTokens


class Revocations:
    def __init__(
        self, delegations: Delegations, access_tokens: AccessTokens, drive_tokens: DriveTokens
    ) -> None:
        self._delegations = delegations
        self._access_tokens = access_tokens
        self._drive_tokens = drive_tokens

    async def revoke(self, user: str) -> None:
        """Revokes the user's delegation, if they have one, then removes the broker from their
        Drive instance.

        Raises InstanceUnavailable when the instance does not answer: the delegation is revoked
        all the same, and keeps its Drive delegation for another try.
        """
        await self._access_tokens.revoke(user)
        await self._drive_tokens.forget_unless_unavailable(user)
        # Only once the broker has left the instance, as the Drive delegation goes with it
        await self._delegations.forget_revoked(user)
