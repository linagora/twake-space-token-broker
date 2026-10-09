"""The consent links the broker gives its users, in its pages and in its problems."""

from urllib.parse import urlencode

CONSENT = "/consent"
"""The plain consent link, relative to the broker: it names nobody."""

SPACE_APP = "space"
"""The app the owner's consent link names, with app=space, when it is for their Space token."""


def consent_link(owner: str, plain: str = CONSENT, *, app: str | None = None) -> str:
    """The consent link bound to its owner, and to the app it is for, if any.

    It extends the plain link given, which is relative to the broker by default.
    """
    query = {"owner": owner} if app is None else {"owner": owner, "app": app}
    return f"{plain}?{urlencode(query)}"
