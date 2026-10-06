"""The users' consent to their agent on their own Drive instance, and its access tokens."""

from dataclasses import replace

from twake_space_token_broker.cozy_stack import CozyStack
from twake_space_token_broker.delegations import Delegations, DriveDelegation
from twake_space_token_broker.tokens import DelegationMissing


class DriveTokens:
    def __init__(self, delegations: Delegations, cozy_stack: CozyStack) -> None:
        self._delegations = delegations
        self._cozy_stack = cozy_stack

    async def request(self, user: str, instance: str, *, state: str, verifier: str) -> str:
        """Registers the broker on the user's Drive instance, and gives where they let it in."""
        client = await self._cozy_stack.register(instance)
        await self._delegations.save_drive(user, DriveDelegation(instance, client, None))
        return self._cozy_stack.authorize_url(instance, client, state=state, verifier=verifier)

    async def consented(self, user: str, code: str, verifier: str) -> None:
        """Keeps the Drive delegation the user granted on their instance."""
        requested = await self._delegations.drive_of(user)
        if requested is None:
            raise DelegationMissing()
        tokens = await self._cozy_stack.redeem(requested.instance, requested.client, code, verifier)
        await self._delegations.save_drive(
            user, replace(requested, refresh_token=tokens.refresh_token)
        )
