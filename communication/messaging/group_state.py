"""Snapshot of a group session's externally-visible state."""

from __future__ import annotations

from dataclasses import dataclass

from shared.ids import AgentId, Epoch


@dataclass
class GroupState:
    """Snapshot every SecureGroupSession exposes; observers must not mutate this."""

    epoch: Epoch
    members: list[AgentId]
    my_index: int
    root_secret: bytes
    # `root_secret` must never be logged or serialised outside the session.
