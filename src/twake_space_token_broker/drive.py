"""The users' consent to their agent on their own Drive instance, and its access tokens."""

import asyncio
import logging
from collections import defaultdict
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace

from twake_space_token_broker.cozy_stack import CozyStack, InstanceRefused, InstanceUnavailable
from twake_space_token_broker.delegations import Delegations, DriveDelegation
from twake_space_token_broker.keys import Undecryptable
from twake_space_token_broker.tokens import DelegationExpired, DelegationMissing, TokenCache

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DriveAccess:
    """What a Drive contract needs to act as the user on their instance."""

    instance: str
    """The host of the user's Drive instance."""
    access_token: str


class DriveTokens:
    def __init__(
        self,
        delegations: Delegations,
        cozy_stack: CozyStack,
        clock: Callable[[], float],
        *,
        reuse_seconds: int,
    ) -> None:
        self._delegations = delegations
        self._cozy_stack = cozy_stack
        self._cache = TokenCache[DriveAccess](clock, reuse_seconds=reuse_seconds)
        self._refreshing: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def forget_even_if_unavailable(self, user: str) -> None:
        """Removes the broker's client from the user's Drive instance, and drops their Drive
        delegation even when the instance does not answer, which then keeps the client."""
        async with self._forgetting(user) as drive:
            if drive is not None:
                try:
                    await self._cozy_stack.unregister(drive.instance, drive.client)
                except InstanceUnavailable as unavailable:
                    logger.warning(
                        "The Drive instance of %s kept an earlier client: %s", user, unavailable
                    )

    async def forget_unless_unavailable(self, user: str) -> None:
        """Removes the broker's client from the user's Drive instance, then drops their Drive
        delegation, which stays for another try when the instance does not answer."""
        async with self._forgetting(user) as drive:
            if drive is not None:
                await self._cozy_stack.unregister(drive.instance, drive.client)

    @asynccontextmanager
    async def _forgetting(self, user: str) -> AsyncIterator[DriveDelegation | None]:
        """The user's Drive delegation, dropped once the block ends without an error."""
        # Under the user's lock, so that a refresh in progress cannot put its token back
        async with self._refreshing[user]:
            self._cache.drop(user)
            try:
                drive = await self._delegations.drive_to_remove(user)
            except Undecryptable:
                # Kept under another ENCRYPTION_KEY: its client stays, for the owner to remove
                drive = None
            yield drive
            await self._delegations.forget_drive(user)

    async def request(self, user: str, instance: str, *, state: str, verifier: str) -> str:
        """Registers the broker on the user's Drive instance, and gives where they let it in."""
        client = await self._cozy_stack.register(instance)
        await self._delegations.save_drive(user, DriveDelegation(instance, client, None))
        return self._cozy_stack.authorize_url(instance, client, state=state, verifier=verifier)

    async def consented(self, user: str, code: str, verifier: str) -> None:
        """Keeps the Drive delegation the user granted on their instance, with its access token."""
        requested = await self._delegations.drive_of(user)
        if requested is None:
            raise DelegationMissing()
        tokens = await self._cozy_stack.redeem(requested.instance, requested.client, code, verifier)
        await self._delegations.save_drive(
            user, replace(requested, refresh_token=tokens.refresh_token)
        )
        self._cache.keep(user, DriveAccess(requested.instance, tokens.access_token), tokens)

    async def of(self, user: str) -> DriveAccess:
        """A fresh access token of the user's Drive instance, for the user's agent."""
        # One refresh at a time per user, as for LemonLDAP's tokens
        async with self._refreshing[user]:
            return self._cache.fresh(user) or await self._refresh(user)

    async def _refresh(self, user: str) -> DriveAccess:
        drive = await self._delegations.drive_of(user)
        if drive is None or drive.refresh_token is None:
            raise DelegationMissing()
        try:
            tokens = await self._cozy_stack.refresh(
                drive.instance, drive.client, drive.refresh_token
            )
        except InstanceRefused as refused:
            # As once the owner removed the broker from the applications of their instance
            logger.warning("The Drive instance of %s refused their delegation (%s)", user, refused)
            raise DelegationExpired() from refused
        if tokens.refresh_token is not None and tokens.refresh_token != drive.refresh_token:
            await self._delegations.save_drive(
                user, replace(drive, refresh_token=tokens.refresh_token)
            )
        access = DriveAccess(instance=drive.instance, access_token=tokens.access_token)
        self._cache.keep(user, access, tokens)
        return access
