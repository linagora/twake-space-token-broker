from fastapi import FastAPI

from twake_space_token_broker import consent
from twake_space_token_broker.keys import Signer
from twake_space_token_broker.lemonldap import LemonLDAP
from twake_space_token_broker.settings import Settings


def create_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="Twake Space token broker", docs_url=None, redoc_url=None)
    app.include_router(consent.router(LemonLDAP(settings), Signer(settings.encryption_key)))
    return app
