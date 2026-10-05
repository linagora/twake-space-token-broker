"""The keys the broker derives from its one secret, and what it does with them."""

import base64
import hashlib
import hmac
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_SIZE = 12


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


def _decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Signer:
    """Signs what the broker gives a browser to keep, such as a consent in progress."""

    def __init__(self, secret: bytes) -> None:
        self._key = _derive(secret, "cookie signing")

    def sign(self, payload: dict[str, Any]) -> str:
        body = _encode(json.dumps(payload).encode())
        return f"{body}.{self._mac(body)}"

    def verify(self, value: str) -> dict[str, Any] | None:
        """What the broker signed, or None when the value was not signed by it."""
        body, _, mac = value.partition(".")
        if not hmac.compare_digest(mac.encode(), self._mac(body).encode()):
            return None
        payload = json.loads(_decode(body))
        return payload if isinstance(payload, dict) else None

    def _mac(self, body: str) -> str:
        return _encode(hmac.new(self._key, body.encode(), hashlib.sha256).digest())


class Cipher:
    """Encrypts a user's refresh token, bound to that user so that it decrypts for no one else."""

    def __init__(self, secret: bytes) -> None:
        self._aead = AESGCM(_derive(secret, "refresh token encryption"))

    def encrypt(self, plaintext: str, *, user: str) -> bytes:
        nonce = os.urandom(NONCE_SIZE)
        return nonce + self._aead.encrypt(nonce, plaintext.encode(), user.encode())
