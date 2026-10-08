import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

KEY_SIZE = 32
"""Bytes of the encryption key, at least: as long as the keys derived from it."""

TOKEN_REUSE_SECONDS = 60
"""The default of Settings.token_reuse_seconds."""

DELEGATION_LIFETIME_SECONDS = 30 * 24 * 3600
"""The default of Settings.delegation_lifetime_seconds: LemonLDAP's default offline session."""

LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
"""One label of a domain name, in lower case."""


@dataclass(frozen=True)
class Settings:
    database_url: str
    issuer: str
    """The LemonLDAP OpenID Connect issuer, such as https://sign-up.example.com/."""
    client_id: str
    client_secret: str
    encryption_key: bytes
    """The one secret every key of the broker derives from."""
    public_base_url: str
    """Where users reach the consent page, such as https://agent-consent.example.com."""
    token_reuse_seconds: int = TOKEN_REUSE_SECONDS
    """Seconds an access token is handed out before LemonLDAP is asked again.

    It bounds how long a revoked delegation still gets tokens, as an access token lasts hours.
    """
    delegation_lifetime_seconds: int = DELEGATION_LIFETIME_SECONDS
    """Seconds a delegation lasts from the consent: the offline session of LemonLDAP's client.

    LemonLDAP 2.21 counts it from the consent, and no refresh extends it.
    """
    drive_instance_domain: str | None = None
    """The domain of the users' Drive instances, such as twake.example.com, or None for no Drive.

    The broker lets itself in only on an instance right under it, <name>.<domain>, since it calls
    the host LemonLDAP names.
    """

    @property
    def redirect_uri(self) -> str:
        return f"{self.public_base_url}/callback"

    @property
    def consent_url(self) -> str:
        return f"{self.public_base_url}/consent"

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Self:
        """Settings from the environment the service runs in."""
        return cls(
            database_url=environ["DATABASE_URL"],
            issuer=environ["OIDC_ISSUER"],
            client_id=environ.get("OIDC_CLIENT_ID", "twake-space-agents"),
            client_secret=environ["OIDC_CLIENT_SECRET"],
            encryption_key=_key(environ["ENCRYPTION_KEY"]),
            public_base_url=environ["PUBLIC_BASE_URL"].rstrip("/"),
            token_reuse_seconds=_seconds(environ, "TOKEN_REUSE_SECONDS", TOKEN_REUSE_SECONDS),
            delegation_lifetime_seconds=_seconds(
                environ, "DELEGATION_LIFETIME_SECONDS", DELEGATION_LIFETIME_SECONDS
            ),
            drive_instance_domain=_domain(environ.get("DRIVE_INSTANCE_DOMAIN", "")),
        )


def _seconds(environ: Mapping[str, str], variable: str, default: int) -> int:
    text = environ.get(variable, str(default))
    if not text.isdecimal():
        raise ValueError(f"{variable} must be a whole number of seconds")
    return int(text)


def _domain(text: str) -> str | None:
    domain = text.strip().lower()
    if not domain:
        return None
    if not re.fullmatch(rf"{LABEL}(?:\.{LABEL})+", domain):
        raise ValueError("DRIVE_INSTANCE_DOMAIN must be a domain name, such as twake.example.com")
    return domain


def _key(encoded: str) -> bytes:
    try:
        key = base64.b64decode(encoded, validate=True)
    except binascii.Error as error:
        raise ValueError("ENCRYPTION_KEY must be base64 encoded") from error
    if len(key) < KEY_SIZE:
        raise ValueError(f"ENCRYPTION_KEY must hold at least {KEY_SIZE} bytes")
    return key
