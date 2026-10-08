"""Each user's consent to their agent, kept as their refresh token, encrypted."""

import json
from dataclasses import dataclass
from datetime import datetime

from psycopg_pool import AsyncConnectionPool

from twake_space_token_broker.cozy_stack import Client
from twake_space_token_broker.keys import Cipher

SCHEMA = (
    """
CREATE TABLE IF NOT EXISTS delegations (
    user_email text PRIMARY KEY,
    refresh_token bytea NOT NULL,
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
    # client set to
    "ALTER TABLE delegations ADD COLUMN IF NOT EXISTS consented_at timestamptz",
    "UPDATE delegations SET consented_at = updated_at WHERE consented_at IS NULL",
    "ALTER TABLE delegations ALTER COLUMN consented_at SET NOT NULL",
)


@dataclass(frozen=True)
class DriveDelegation:
    """The user's consent to their agent on their Drive instance."""

    instance: str
    """The host of the user's Drive instance."""
    client: Client
    refresh_token: str | None
    """None until the user grants the client access on their instance."""


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
        """When the user consented, if they did."""
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                "SELECT consented_at FROM delegations WHERE user_email = %s", (user,)
            )
            row = await cursor.fetchone()
        return None if row is None else row[0]

    async def refresh_token_of(self, user: str) -> str | None:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                "SELECT refresh_token FROM delegations WHERE user_email = %s", (user,)
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
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                "SELECT credentials FROM drive_delegations WHERE user_email = %s", (user,)
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        credentials = json.loads(self._cipher.decrypt(row[0], user=user))
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
