"""PKCE (RFC 7636), which ties an authorization code to the consent that asked for it."""

import hashlib

from twake_space_token_broker import base64url


def challenge(verifier: str) -> str:
    """The S256 challenge of a verifier."""
    return base64url.encode(hashlib.sha256(verifier.encode()).digest())
