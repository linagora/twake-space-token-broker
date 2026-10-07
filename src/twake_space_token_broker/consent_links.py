"""The consent links the broker gives its users, in its pages and in its problems."""

from urllib.parse import urlencode

CONSENT = "/consent"
"""The plain consent link, relative to the broker: it names nobody."""


def consent_link(owner: str, plain: str = CONSENT) -> str:
    """The consent link bound to its owner.

    It extends the plain link given, which is relative to the broker by default.
    """
    return f"{plain}?{urlencode({'owner': owner})}"
