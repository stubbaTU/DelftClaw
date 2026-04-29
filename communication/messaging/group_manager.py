"""Convenience facade over a SecureGroupSession; what TrustroomCommunity holds."""

from __future__ import annotations

from communication.messaging.secure_group_session import SecureGroupSession
from shared.credentials import KeyBundle
from shared.ids import AgentId


class GroupManager:
    """Wraps a SecureGroupSession with verb-shaped names matching admin operations."""

    def __init__(self, session: SecureGroupSession) -> None:
        # Hold the underlying session so all verbs delegate to it.
        ...

    def add(self, candidate: KeyBundle) -> bytes:
        # Delegate to session.add_member; return the commit blob to broadcast.
        ...

    def remove(self, agent: AgentId) -> bytes:
        # Delegate to session.remove_member; return the commit blob to broadcast.
        ...

    def rotate(self) -> bytes:
        # Trigger a proactive group-key rotation (post-compromise security); return commit blob.
        ...
