"""The users' consent to their agent on their own Drive instance, and its access tokens."""

import asyncio
import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, replace

from twake_space_token_broker.cozy_stack import CozyStack, InstanceRefused, InstanceUnavailable
from twake_space_token_broker.delegations import Delegations, DriveDelegation
from twake_space_token_broker.keys import Undecryptable
from twake_space_token_broker.lemonldap import Tokens
from twake_space_token_broker.tokens import DelegationExpired, DelegationMissing, reusable_until

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DriveAccess:
    """What a Drive contract needs to act as the user on their instance."""

    instance: str
    """The host of the user's Drive instance."""
    access_token: str


@dataclass(frozen=True)
class _Cached:
    access: DriveAccess
    reusable_until: float


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
        self._clock = clock
        self._reuse_seconds = reuse_seconds
        self._cache: dict[str, _Cached] = {}
        self._refreshing: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def forget(self, user: str) -> None:
        """Drops the user's Drive delegation, and removes its client from the instance."""
        # Under the user's lock, so that a refresh in progress cannot put its token back
        async with self._refreshing[user]:
            try:
                earlier = await self._delegations.drive_of(user)
            except Undecryptable:
                # Kept under another ENCRYPTION_KEY: its client stays, for the owner to remove
                earlier = None
            await self._delegations.forget_drive(user)
            self._cache.pop(user, None)
        if earlier is None:
            return
        try:
            await self._cozy_stack.unregister(earlier.instance, earlier.client)
        except InstanceUnavailable as unavailable:
            logger.warning("The Drive instance of %s kept an earlier client: %s", user, unavailable)

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
        self._keep(user, requested.instance, tokens)

    async def of(self, user: str) -> DriveAccess:
        """A fresh access token of the user's Drive instance, for the user's agent."""
        # One refresh at a time per user, as for LemonLDAP's tokens
        async with self._refreshing[user]:
            return self._fresh(user) or await self._refresh(user)

    def _fresh(self, user: str) -> DriveAccess | None:
        cached = self._cache.get(user)
        if cached is not None and self._clock() < cached.reusable_until:
            return cached.access
        return None

    def _keep(self, user: str, instance: str, tokens: Tokens) -> None:
        self._cache[user] = _Cached(
            access=DriveAccess(instance=instance, access_token=tokens.access_token),
            reusable_until=reusable_until(tokens, self._reuse_seconds),
        )

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
        self._keep(user, drive.instance, tokens)
        return DriveAccess(instance=drive.instance, access_token=tokens.access_token)
