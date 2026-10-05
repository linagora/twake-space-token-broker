"""The keys the broker derives from its one secret, and what it does with them."""

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _derive(secret: bytes, purpose: str) -> bytes:
    """A key for one purpose only, so that no key ever serves two."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"twake-space-token-broker {purpose}".encode(),
    )
    return hkdf.derive(secret)


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class Signer:
    """Signs what the broker gives a browser to keep, such as a consent in progress."""

    def __init__(self, secret: bytes) -> None:
        self._key = _derive(secret, "cookie signing")

    def sign(self, payload: dict[str, Any]) -> str:
        body = _encode(json.dumps(payload).encode())
        return f"{body}.{self._mac(body)}"

    def _mac(self, body: str) -> str:
        return _encode(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
