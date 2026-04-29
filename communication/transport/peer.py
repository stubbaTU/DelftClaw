"""Lightweight Peer wrapper that exposes our AgentId and hides ipv8.Peer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shared.ids import AgentId


@dataclass(frozen=True)
class Peer:
    """Domain-level peer representation; AgentId is derived from the IPv8 Ed25519 pubkey."""

    agent_id: AgentId
    pubkey: bytes

    @classmethod
    def from_ipv8(cls, p: Any) -> "Peer":
        # Adapt an ipv8.Peer to our domain Peer; AgentId == hash(pubkey).
        ...
