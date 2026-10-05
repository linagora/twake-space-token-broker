from dataclasses import dataclass


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
