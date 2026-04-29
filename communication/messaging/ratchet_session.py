"""Path B (ADR 0003): pure-Python forward-secret ratchet.

HKDF chain key + Ed25519 sig key + per-epoch group key. NOT RFC 9420
conformant — used only if Path A is not feasible by 2026-05-08.
"""

from __future__ import annotations

from communication.messaging.group_state import GroupState
from communication.messaging.secure_group_session import SecureGroupSession
from identity.agent_identity import AgentIdentity
from shared.credentials import KeyBundle
from shared.ids import AgentId, RoomId


class RatchetSession(SecureGroupSession):
    """Pure-Python fallback satisfying SecureGroupSession (Path B, ADR 0003)."""

    def __init__(self, identity: AgentIdentity, room_id: RoomId) -> None:
        # Hold identity + room id; initialise empty state until bootstrap or install_welcome.
        ...

    @property
    def state(self) -> GroupState:
        # Return the current GroupState snapshot.
        ...

    def bootstrap(self, members: list[KeyBundle]) -> bytes:
        # Generate root secret, derive epoch-0 keys, package a welcome blob per founder.
        ...

    def install_welcome(self, welcome_blob: bytes) -> None:
        # Decrypt the welcome blob, install root secret, advance to the welcome's epoch.
        ...

    def add_member(self, candidate: KeyBundle) -> bytes:
        # Append candidate, run HKDF to advance, sign new state with mls key, return commit blob.
        ...

    def remove_member(self, agent: AgentId) -> bytes:
        # Drop agent, advance HKDF chain (post-compromise security), return commit blob.
        ...

    def apply_commit(self, commit_blob: bytes) -> None:
        # Verify signature, apply add/remove, advance local epoch and chain key.
        ...

    def encrypt(self, plaintext: bytes) -> bytes:
        # AEAD encrypt under per-(epoch, sender) key derived from chain key; advance chain key.
        ...

    def decrypt(self, ciphertext: bytes, sender: AgentId) -> bytes:
        # Look up sender's per-epoch chain, decrypt, raise EpochMismatch on stale epoch.
        ...
