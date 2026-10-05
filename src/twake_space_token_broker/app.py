from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool

from twake_space_token_broker import consent
from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.keys import Cipher, Signer
from twake_space_token_broker.lemonldap import LemonLDAP
from twake_space_token_broker.settings import Settings


def create_app(
    settings: Settings, *, lemonldap_transport: httpx.AsyncBaseTransport | None = None
) -> FastAPI:
    pool = AsyncConnectionPool(settings.database_url, open=False)
    http = httpx.AsyncClient(transport=lemonldap_transport, timeout=10.0)
    delegations = Delegations(pool, Cipher(settings.encryption_key))
    lemonldap = LemonLDAP(settings, http)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await pool.open()
        await delegations.create_schema()
        yield
        await pool.close()
        await http.aclose()

    app = FastAPI(
        title="Twake Space token broker", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    app.include_router(consent.router(lemonldap, Signer(settings.encryption_key), delegations))
    return app
