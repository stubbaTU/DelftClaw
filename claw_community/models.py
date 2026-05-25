from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CommunityMember:
    agent_id: str
    wallet_address: str
    joined_at: str
    donation_txid: str
    donated_sats: int
    initial_trust: float
    assigned_seedbox_id: str | None = None


@dataclass
class CommunityTreasury:
    wallet_address: str
    balance_sats: int = 0
    incoming_sats: int = 0
    outgoing_sats: int = 0


@dataclass
class CommunitySeedbox:
    seedbox_id: str
    provider: str
    machine_id: str
    hostname: str
    ip: str
    content_dir: str
    health_status: str
    capacity_agents: int
    logs_path: str
    created_at: str


@dataclass
class CommunityFile:
    file_id: str
    name: str
    tags: tuple[str, ...]
    sha256: str
    size_bytes: int
    seedbox_id: str
    content_url: str
    magnet_uri: str


@dataclass
class Community:
    community_id: str
    founder_agent_id: str
    treasury: CommunityTreasury
    join_fee_sats: int
    seedbox_capacity_agents: int
    seedbox_purchase_threshold_sats: int
    members: dict[str, CommunityMember] = field(default_factory=dict)
    seedboxes: dict[str, CommunitySeedbox] = field(default_factory=dict)
    files: dict[str, CommunityFile] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)

    def member_count(self) -> int:
        return len(self.members)

    def seedbox_count(self) -> int:
        return len(self.seedboxes)

    def required_seedbox_count(self) -> int:
        if not self.members:
            return 1 if self.seedboxes else 0
        return (len(self.members) + self.seedbox_capacity_agents - 1) // self.seedbox_capacity_agents
