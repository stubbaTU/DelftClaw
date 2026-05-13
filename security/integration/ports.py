from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class SecurityIdentity:
    """Security-owned identity snapshot.

    Identity/communication teams can fill the optional public-key fields later.
    Security code only requires a stable agent_id.
    """

    agent_id: str
    network: str = ""
    identity_hash: str = ""
    ipv8_public_key: str = ""
    app_public_key: str = ""
    wallet_public_key: str = ""


class IdentityProvider(Protocol):
    def current_identity(self) -> SecurityIdentity:
        """Return the local agent identity used to attribute security evidence."""


class EvidencePublisher(Protocol):
    def publish(self, event: dict[str, Any]) -> None:
        """Publish a verified append-only-log event to peers, if networking exists."""


@dataclass
class StaticIdentityProvider:
    identity: SecurityIdentity

    def current_identity(self) -> SecurityIdentity:
        return self.identity


@dataclass
class AgentIdentityProvider:
    """Adapter from the shared identity.AgentIdentity bundle to security ports."""

    identity: Any

    def current_identity(self) -> SecurityIdentity:
        bundle = self.identity.public_bundle()
        return SecurityIdentity(
            agent_id=str(bundle["agent_id"]),
            network=str(bundle.get("network", "")),
            identity_hash=str(bundle["agent_id"]),
            ipv8_public_key=str(bundle.get("ipv8_pubkey", "")),
            app_public_key=str(bundle.get("app_pubkey", "")),
            wallet_public_key=str(bundle.get("wallet_xpub", "")),
        )


@dataclass
class NoopEvidencePublisher:
    published: list[dict[str, Any]] = field(default_factory=list)

    def publish(self, event: dict[str, Any]) -> None:
        self.published.append(dict(event))
