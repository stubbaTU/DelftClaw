"""Parent-replica delegation chains and the manager that produces them."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from identity.agent_identity import AgentIdentity
from shared.ids import AgentId


@dataclass(frozen=True)
class DelegationLink:
    """One signed link in a parent→child delegation chain."""

    parent: AgentId
    child: AgentId
    issued_at: datetime
    parent_signature: bytes
    # `parent_signature` is the parent's MLS sig over (parent, child, issued_at).


@dataclass(frozen=True)
class ReplicaRelationship:
    """Full chain back to the root principal; SQ3 provenance experiments inspect this."""

    parent: AgentId
    child: AgentId
    chain: list[DelegationLink]


class ReplicaManager:
    """Spawns replicas and verifies inbound delegation chains."""

    def __init__(self, parent_identity: AgentIdentity) -> None:
        # Hold the parent identity so spawn_replica can sign DelegationLinks.
        ...

    def spawn_replica(
        self,
        replica_index: int,
    ) -> tuple[AgentIdentity, DelegationLink]:
        # Derive a child Seed, build a child AgentIdentity, sign a DelegationLink with parent.mls.
        ...

    def verify_chain(self, chain: list[DelegationLink]) -> bool:
        # Walk every link and validate each parent_signature; used by SQ3 provenance-lie tests.
        ...
