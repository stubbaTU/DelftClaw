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
        """Adapt an ``ipv8.peer.Peer`` to our domain Peer.

        The 32-byte raw Ed25519 verify key (``public_key.veri.vk`` for LibNaCLPK)
        is the canonical AgentId backing.
        """
        pub = p.public_key
        raw = pub.veri.vk if hasattr(pub, "veri") else pub.key_to_bin()[-32:]
        return cls(agent_id=AgentId.from_pubkey(raw), pubkey=raw)
