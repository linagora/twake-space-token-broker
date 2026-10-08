"""The owner's delegation, which their agent's harness reads and revokes through APISIX."""

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Response

from twake_space_token_broker.consent_links import consent_link
from twake_space_token_broker.cozy_stack import InstanceUnavailable
from twake_space_token_broker.delegations import Delegations
from twake_space_token_broker.drive import DriveTokens
from twake_space_token_broker.forward_auth import Owner
from twake_space_token_broker.problems import Problem
from twake_space_token_broker.tokens import AccessTokens

logger = logging.getLogger(__name__)


def _instant(moment: datetime) -> str:
    """A moment in UTC, to the second, as RFC 3339 writes it."""
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def router(
    delegations: Delegations,
    access_tokens: AccessTokens,
    drive_tokens: DriveTokens,
    consent_url: str,
    *,
    lifetime_seconds: int,
) -> APIRouter:
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
                detail="The owner has no delegation: they must open the consent link to let their"
                " agent act for them.",
                extensions={"consent_url": consent_link(owner, consent_url)},
            )
        return {
            "consented_at": _instant(consented_at),
            "expires_at": _instant(consented_at + lifetime),
            "consent_url": consent_link(owner, consent_url),
        }

    @routes.delete("/delegation", status_code=204)
    async def revoke(owner: Owner) -> Response:
        """Revokes the owner's delegation, if they have one, then removes the broker from their
        Drive instance."""
        await access_tokens.revoke(owner)
        try:
            await drive_tokens.revoke(owner)
        except InstanceUnavailable as unavailable:
            logger.warning("The Drive instance of %s kept the broker: %s", owner, unavailable)
            raise Problem(
                status=502,
                code="drive_unavailable",
                title="Drive unavailable",
                detail="The owner's Drive instance did not answer: their delegation is revoked,"
                " but the broker stays on the instance until the revocation is tried again.",
            ) from unavailable
        await delegations.forget_revoked(owner)
        return Response(status_code=204)

    return routes
