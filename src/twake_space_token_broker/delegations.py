"""Each user's consent to their agent, kept as their refresh token, encrypted."""

from psycopg_pool import AsyncConnectionPool

from twake_space_token_broker.keys import Cipher

SCHEMA = """
CREATE TABLE IF NOT EXISTS delegations (
    user_email text PRIMARY KEY,
    refresh_token bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
)
"""


class Delegations:
    def __init__(self, pool: AsyncConnectionPool, cipher: Cipher) -> None:
        self._pool = pool
        self._cipher = cipher

    async def create_schema(self) -> None:
        async with self._pool.connection() as connection:
            await connection.execute(SCHEMA)

    async def save(self, user: str, refresh_token: str) -> None:
        async with self._pool.connection() as connection:
            await connection.execute(
                "INSERT INTO delegations (user_email, refresh_token) VALUES (%s, %s)",
                (user, self._cipher.encrypt(refresh_token, user=user)),
            )

    async def refresh_token_of(self, user: str) -> str | None:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                "SELECT refresh_token FROM delegations WHERE user_email = %s", (user,)
            )
            row = await cursor.fetchone()
        return None if row is None else self._cipher.decrypt(row[0], user=user)
