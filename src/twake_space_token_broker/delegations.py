"""Each user's consent to their agent, kept as their refresh token, encrypted."""

import json
from dataclasses import dataclass
from datetime import datetime

from psycopg_pool import AsyncConnectionPool

from twake_space_token_broker.cozy_stack import Client
from twake_space_token_broker.keys import Cipher

SCHEMA = (
    # A revoked delegation keeps no refresh token, and stays only until the broker has removed its
    # client from the user's Drive instance
    """
CREATE TABLE IF NOT EXISTS delegations (
    user_email text PRIMARY KEY,
    refresh_token bytea,
    consented_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
)
""",
    # A Drive delegation belongs to the user's delegation, and goes with it
    """
CREATE TABLE IF NOT EXISTS drive_delegations (
    user_email text PRIMARY KEY REFERENCES delegations ON DELETE CASCADE,
    credentials bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
)
""",
    # The delegations of a broker of before consent dates take their last change as theirs: a
    # refresh changed them only when LemonLDAP rotated the refresh token, which it does only for a
    # client set to rotate its refresh tokens
    "ALTER TABLE delegations ADD COLUMN IF NOT EXISTS consented_at timestamptz",
    "UPDATE delegations SET consented_at = updated_at WHERE consented_at IS NULL",
    "ALTER TABLE delegations ALTER COLUMN consented_at SET NOT NULL",
    # A broker of before revocations kept a refresh token in each delegation
    "ALTER TABLE delegations ALTER COLUMN refresh_token DROP NOT NULL",
    # The Twake Space token the user pasted, with the scopes the broker saw it hold: it goes as
    # soon as the user revokes their delegation, but a new consent keeps it
    """
CREATE TABLE IF NOT EXISTS space_tokens (
    user_email text PRIMARY KEY REFERENCES delegations ON DELETE CASCADE,
    token bytea NOT NULL,
    scopes text[] NOT NULL,
    pasted_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
)
""",
)

REVOKED = "refresh_token IS NULL"
"""The SQL condition met by a revoked delegation, which keeps no refresh token."""


@dataclass(frozen=True)
class DriveDelegation:
    """The user's consent to their agent on their Drive instance."""

    instance: str
    """The host of the user's Drive instance."""
    client: Client
    refresh_token: str | None
    """None until the user grants the client access on their instance."""


@dataclass(frozen=True)
class SpaceToken:
    """The Space token the user pasted, with the scopes the broker saw it hold, and when."""

    token: str
    scopes: frozenset[str]
    pasted_at: datetime


class Delegations:
    def __init__(self, pool: AsyncConnectionPool, cipher: Cipher) -> None:
        self._pool = pool
        self._cipher = cipher

    async def create_schema(self) -> None:
        async with self._pool.connection() as connection:
            for statement in SCHEMA:
                await connection.execute(statement)

    async def save(self, user: str, refresh_token: str, *, consented_at: datetime) -> None:
        """Keeps the user's new consent in place of any earlier one."""
        async with self._pool.connection() as connection:
            await connection.execute(
                "INSERT INTO delegations (user_email, refresh_token, consented_at)"
                " VALUES (%s, %s, %s)"
                " ON CONFLICT (user_email) DO UPDATE"
                " SET refresh_token = EXCLUDED.refresh_token,"
                " consented_at = EXCLUDED.consented_at, updated_at = now()",
                (user, self._cipher.encrypt(refresh_token, user=user), consented_at),
            )

    async def replace_refresh_token(self, user: str, refresh_token: str) -> None:
        """Keeps the refresh token LemonLDAP rotated, under the same consent."""
        async with self._pool.connection() as connection:
            await connection.execute(
                "UPDATE delegations SET refresh_token = %s, updated_at = now()"
                " WHERE user_email = %s",
                (self._cipher.encrypt(refresh_token, user=user), user),
            )

    async def consented_at(self, user: str) -> datetime | None:
        """When the user consented, unless they never did or revoked it since."""
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                f"SELECT consented_at FROM delegations WHERE user_email = %s AND NOT ({REVOKED})",
                (user,),
            )
            row = await cursor.fetchone()
        return None if row is None else row[0]

    async def revoke(self, user: str) -> None:
        """Drops the user's refresh token and their Space token: their Drive delegation stays,
        until the broker has removed its client from their instance."""
        async with self._pool.connection() as connection:
            await connection.execute(
                "UPDATE delegations SET refresh_token = NULL, updated_at = now()"
                " WHERE user_email = %s",
                (user,),
            )
            # Else a new consent would serve it again, until the broker leaves the instance
            await connection.execute("DELETE FROM space_tokens WHERE user_email = %s", (user,))

    async def forget_revoked(self, user: str) -> None:
        """Forgets the user's revoked delegation, unless they consented again since."""
        async with self._pool.connection() as connection:
            await connection.execute(
                f"DELETE FROM delegations WHERE user_email = %s AND {REVOKED}", (user,)
            )

    async def refresh_token_of(self, user: str) -> str | None:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                f"SELECT refresh_token FROM delegations WHERE user_email = %s AND NOT ({REVOKED})",
                (user,),
            )
            row = await cursor.fetchone()
        return None if row is None else self._cipher.decrypt(row[0], user=user)

    async def save_drive(self, user: str, drive: DriveDelegation) -> None:
        """Keeps the user's Drive delegation, beside their delegation, which must exist."""
        credentials = {
            "instance": drive.instance,
            "client_id": drive.client.client_id,
            "client_secret": drive.client.client_secret,
            "registration_access_token": drive.client.registration_access_token,
            "refresh_token": drive.refresh_token,
        }
        async with self._pool.connection() as connection:
            await connection.execute(
                "INSERT INTO drive_delegations (user_email, credentials) VALUES (%s, %s)"
                " ON CONFLICT (user_email) DO UPDATE"
                " SET credentials = EXCLUDED.credentials, updated_at = now()",
                (user, self._cipher.encrypt(json.dumps(credentials), user=user)),
            )

    async def drive_of(self, user: str) -> DriveDelegation | None:
        """The user's Drive delegation, unless they revoked their delegation."""
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                "SELECT credentials FROM drive_delegations JOIN delegations USING (user_email)"
                f" WHERE user_email = %s AND NOT ({REVOKED})",
                (user,),
            )
            row = await cursor.fetchone()
        return None if row is None else self._drive(row[0], user)

    async def drive_to_remove(self, user: str) -> DriveDelegation | None:
        """The user's Drive delegation, even once they revoked their delegation: the broker keeps
        it until it has removed its client from their instance."""
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                "SELECT credentials FROM drive_delegations WHERE user_email = %s", (user,)
            )
            row = await cursor.fetchone()
        return None if row is None else self._drive(row[0], user)

    def _drive(self, encrypted: bytes, user: str) -> DriveDelegation:
        credentials = json.loads(self._cipher.decrypt(encrypted, user=user))
        return DriveDelegation(
            instance=credentials["instance"],
            client=Client(
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
                registration_access_token=credentials["registration_access_token"],
            ),
            refresh_token=credentials["refresh_token"],
        )

    async def forget_drive(self, user: str) -> None:
        async with self._pool.connection() as connection:
            await connection.execute("DELETE FROM drive_delegations WHERE user_email = %s", (user,))

    async def save_space_token(
        self, user: str, token: str, *, scopes: list[str], pasted_at: datetime
    ) -> bool:
        """Keeps the Space token the user pasted in place of any earlier one, beside their
        delegation: False, and nothing kept, when they have none or revoked it."""
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                "INSERT INTO space_tokens (user_email, token, scopes, pasted_at)"
                " SELECT user_email, %s, %s, %s FROM delegations"
                f" WHERE user_email = %s AND NOT ({REVOKED})"
                " ON CONFLICT (user_email) DO UPDATE"
                " SET token = EXCLUDED.token, scopes = EXCLUDED.scopes,"
                " pasted_at = EXCLUDED.pasted_at, updated_at = now()",
                (self._cipher.encrypt(token, user=user), scopes, pasted_at, user),
            )
        return cursor.rowcount == 1

    async def space_token_of(self, user: str) -> SpaceToken | None:
        """The Space token the user pasted, unless they revoked their delegation."""
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                "SELECT token, scopes, pasted_at FROM space_tokens JOIN delegations"
                f" USING (user_email) WHERE user_email = %s AND NOT ({REVOKED})",
                (user,),
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        token, scopes, pasted_at = row
        return SpaceToken(self._cipher.decrypt(token, user=user), frozenset(scopes), pasted_at)

    async def forget_space_token(self, user: str) -> None:
        async with self._pool.connection() as connection:
            await connection.execute("DELETE FROM space_tokens WHERE user_email = %s", (user,))
