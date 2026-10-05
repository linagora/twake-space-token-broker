import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager

import psycopg
import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient, Response
from psycopg import sql
from psycopg.conninfo import make_conninfo
from testcontainers.community.postgres import PostgresContainer

from tests.fake_lemonldap import FakeLemonLDAP
from twake_space_token_broker.app import create_app
from twake_space_token_broker.settings import Settings

ISSUER = "https://sign-up.example.test/"
PUBLIC_BASE_URL = "https://agent-consent.example.test"
CLIENT_ID = "twake-space-agents"
CLIENT_SECRET = "client-secret-for-tests"

MMAUDET = "mmaudet@example.test"
ALICE = "alice@example.test"


class FakeClock:
    """The time the broker reads, in seconds since the epoch, moved on by the test only."""

    def __init__(self) -> None:
        self.now = 1_790_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(scope="session")
def postgres() -> Iterator[PostgresContainer]:
    with PostgresContainer("postgres:18-alpine", driver=None) as postgres:
        yield postgres


@pytest.fixture
def database_url(postgres: PostgresContainer) -> Iterator[str]:
    """An empty database of its own for each test."""
    server = postgres.get_connection_url()
    name = f"broker_{uuid.uuid4().hex}"
    with psycopg.connect(server, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    yield make_conninfo(server, dbname=name)
    with psycopg.connect(server, autocommit=True) as connection:
        connection.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))


@pytest.fixture
def settings(database_url: str) -> Settings:
    return Settings(
        database_url=database_url,
        issuer=ISSUER,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        encryption_key=bytes(range(32)),
        public_base_url=PUBLIC_BASE_URL,
    )


@pytest.fixture
def lemonldap() -> FakeLemonLDAP:
    return FakeLemonLDAP(issuer=ISSUER, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@asynccontextmanager
async def running(
    settings: Settings, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> AsyncIterator[AsyncClient]:
    """The broker, from its start to its stop."""
    app = create_app(settings, lemonldap_transport=lemonldap.transport, clock=clock)
    async with (
        LifespanManager(app) as manager,
        AsyncClient(transport=ASGITransport(app=manager.app), base_url=PUBLIC_BASE_URL) as client,
    ):
        yield client


@pytest.fixture
async def client(
    settings: Settings, lemonldap: FakeLemonLDAP, clock: FakeClock
) -> AsyncIterator[AsyncClient]:
    async with running(settings, lemonldap, clock) as client:
        yield client


async def consent(client: AsyncClient, lemonldap: FakeLemonLDAP, user: str) -> Response:
    """The user opens the consent link in their own browser and signs in."""
    client.cookies.clear()
    started = await client.get("/consent")
    return await client.get(lemonldap.sign_in(started.headers["location"], user))


def as_agent_of(user: str) -> dict[str, str]:
    """The header APISIX sets on a forward-auth request, naming the agent's owner."""
    return {"X-Twake-User-Email": user}


async def database_dump(database_url: str) -> str:
    """Every row of every table, as PostgreSQL prints them."""
    async with await psycopg.AsyncConnection.connect(database_url) as connection:
        tables = await connection.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        )
        rows: list[str] = []
        for (table,) in await tables.fetchall():
            select = sql.SQL("SELECT t::text FROM {} AS t").format(sql.Identifier(table))
            rows.extend(row for (row,) in await (await connection.execute(select)).fetchall())
        return "\n".join(rows)
