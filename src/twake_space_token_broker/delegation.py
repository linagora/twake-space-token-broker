"""The owner's delegation, which their agent's harness reads through APISIX."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter

from twake_space_token_broker.consent_links import consent_link
from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.forward_auth import Owner
from twake_space_token_broker.problems import Problem


def _instant(moment: datetime) -> str:
    """A moment in UTC, to the second, as RFC 3339 writes it."""
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def router(delegations: Delegations, consent_url: str, *, lifetime_seconds: int) -> APIRouter:
    routes = APIRouter()
    lifetime = timedelta(seconds=lifetime_seconds)

    @routes.get("/delegation")
    async def status(owner: Owner) -> dict[str, str]:
        """When the owner consented and when their delegation expires, even if it has."""
        consented_at = await delegations.consented_at(owner)
        if consented_at is None:
            raise Problem(
                status=404,
                code="delegation_missing",
                title="Delegation missing",
                detail="The user has not let their agent act for them yet: they must open the"
                " consent link.",
                extensions={"consent_url": consent_link(owner, consent_url)},
            )
        return {
            "consented_at": _instant(consented_at),
            "expires_at": _instant(consented_at + lifetime),
            "consent_url": consent_link(owner, consent_url),
        }

    return routes
