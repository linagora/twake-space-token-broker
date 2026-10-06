"""What the broker's two OAuth clients share, LemonLDAP's and that of the Drive instances."""

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class Tokens:
    access_token: str
    requested_at: float
    """When the broker asked for them, in seconds since the epoch."""
    expires_at: float
    """When the access token expires, in seconds since the epoch."""
    refresh_token: str | None


def json_object(response: httpx.Response) -> dict[str, Any]:
    """The JSON object an answer holds, or an empty one, such as for an error page."""
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}
