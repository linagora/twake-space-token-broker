"""LemonLDAP, the OpenID Connect provider, as the broker's own client sees it."""

from urllib.parse import urlencode

from twake_space_token_broker.settings import Settings

SCOPE = "openid email offline_access"


class LemonLDAP:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def _endpoint(self, path: str) -> str:
        return f"{self._settings.issuer.rstrip('/')}/oauth2/{path}"

    def authorize_url(self, *, state: str, code_challenge: str) -> str:
        """Where the user signs in, to grant the broker offline access with PKCE."""
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._settings.client_id,
                "redirect_uri": self._settings.redirect_uri,
                "scope": SCOPE,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{self._endpoint('authorize')}?{query}"
