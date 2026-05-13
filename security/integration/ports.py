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
class NoopEvidencePublisher:
    published: list[dict[str, Any]] = field(default_factory=list)

    def publish(self, event: dict[str, Any]) -> None:
        self.published.append(dict(event))
