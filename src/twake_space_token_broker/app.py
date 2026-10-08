import os
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool

from twake_space_token_broker import consent, delegation, forward_auth, problems
from twake_space_token_broker.cozy_stack import CozyStack
from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.drive import DriveTokens
from twake_space_token_broker.keys import Cipher, Signer
from twake_space_token_broker.lemonldap import LemonLDAP
from twake_space_token_broker.settings import Settings
from twake_space_token_broker.tokens import AccessTokens


def create_app(
    settings: Settings,
    *,
    lemonldap_transport: httpx.AsyncBaseTransport | None = None,
    cozy_stack_transport: httpx.AsyncBaseTransport | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    pool = AsyncConnectionPool(settings.database_url, open=False)
    http = httpx.AsyncClient(transport=lemonldap_transport, timeout=10.0)
    instances_http = httpx.AsyncClient(transport=cozy_stack_transport, timeout=10.0)
    delegations = Delegations(pool, Cipher(settings.encryption_key))
    lemonldap = LemonLDAP(settings, http, clock)
    access_tokens = AccessTokens(
        delegations, lemonldap, clock, reuse_seconds=settings.token_reuse_seconds
    )
    cozy_stack = CozyStack(
        instances_http,
        clock,
        redirect_uri=settings.redirect_uri,
        client_uri=settings.public_base_url,
    )
    drive_tokens = DriveTokens(
        delegations, cozy_stack, clock, reuse_seconds=settings.token_reuse_seconds
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async with pool, http, instances_http:
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

    app.include_router(
        consent.router(
            lemonldap, Signer(settings.encryption_key), access_tokens, drive_tokens, clock
        )
    )
    app.include_router(
        forward_auth.router(access_tokens, drive_tokens, lemonldap, settings.consent_url)
    )
    app.include_router(
        delegation.router(
            delegations,
            access_tokens,
            drive_tokens,
            settings.consent_url,
            lifetime_seconds=settings.delegation_lifetime_seconds,
        )
    )
    return app


def create_app_from_env() -> FastAPI:
    """Entry point for uvicorn --factory, configured by the environment."""
    return create_app(Settings.from_env(os.environ))
