import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool

from twake_space_token_broker import consent, forward_auth, problems
from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.keys import Cipher, Signer
from twake_space_token_broker.lemonldap import LemonLDAP
from twake_space_token_broker.settings import Settings
from twake_space_token_broker.tokens import AccessTokens


def create_app(
    settings: Settings,
    *,
    lemonldap_transport: httpx.AsyncBaseTransport | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    pool = AsyncConnectionPool(settings.database_url, open=False)
    http = httpx.AsyncClient(transport=lemonldap_transport, timeout=10.0)
    delegations = Delegations(pool, Cipher(settings.encryption_key))
    lemonldap = LemonLDAP(settings, http, clock)
    tokens = AccessTokens(delegations, lemonldap, clock)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async with pool, http:
            await delegations.create_schema()
            yield

    app = FastAPI(
        title="Twake Space token broker", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    problems.install(app)

    @app.get("/healthz", include_in_schema=False)
    async def health() -> dict[str, str]:
        """For the probes of Kubernetes."""
        return {"status": "ok"}

    app.include_router(consent.router(lemonldap, Signer(settings.encryption_key), tokens, clock))
    app.include_router(forward_auth.router(tokens, settings.consent_url))
    return app
