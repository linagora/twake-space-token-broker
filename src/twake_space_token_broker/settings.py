import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

KEY_SIZE = 32
"""Bytes of the encryption key, at least: as long as the keys derived from it."""


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
        )


def _key(encoded: str) -> bytes:
    try:
        key = base64.b64decode(encoded, validate=True)
    except binascii.Error as error:
        raise ValueError("ENCRYPTION_KEY must be base64 encoded") from error
    if len(key) < KEY_SIZE:
        raise ValueError(f"ENCRYPTION_KEY must hold at least {KEY_SIZE} bytes")
    return key
