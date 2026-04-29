"""The Layer-4 contract.

Both `MLSSession` (Path A, RFC 9420) and `RatchetSession` (Path B, HKDF + Ed25519
fallback) satisfy this Protocol. ADR 0003 picks one as the default by 2026-05-08.
"""

from __future__ import annotations

from typing import Protocol

from communication.messaging.group_state import GroupState
from identity.agent_identity import AgentIdentity
from shared.credentials import KeyBundle
from shared.ids import AgentId, RoomId


class SecureGroupSession(Protocol):
    """Encryption + group-state contract for a single Trustroom."""

    @property
    def state(self) -> GroupState:
        # Current epoch, member list, my index, current root secret.
        ...

    def bootstrap(self, members: list[KeyBundle]) -> bytes:
        # Set up a fresh group with given founder members; return a welcome blob deliverable to them.
        ...

    def install_welcome(self, welcome_blob: bytes) -> None:
        # Consume a welcome blob produced by bootstrap or add_member, and join the group.
        ...

    def add_member(self, candidate: KeyBundle) -> bytes:
        # Produce a commit blob admitting candidate; the caller broadcasts it.
        ...

    def remove_member(self, agent: AgentId) -> bytes:
        # Produce a commit blob evicting `agent`.
        ...

    def apply_commit(self, commit_blob: bytes) -> None:
        # Apply a commit produced by another member; advances epoch.
        ...

    def encrypt(self, plaintext: bytes) -> bytes:
        # AEAD-encrypt under current sender key; bind ciphertext to (epoch, sender_index).
        ...

    def decrypt(self, ciphertext: bytes, sender: AgentId) -> bytes:
        # Peer decryption; raise EpochMismatch if the ciphertext is from a non-current epoch.
        ...


class SecureGroupSessionFactory(Protocol):
    """Builds a SecureGroupSession instance for a fresh or joined room."""

    def new(self, identity: AgentIdentity, room_id: RoomId) -> SecureGroupSession:
        # Called by TrustroomCommunity when creating or joining a room.
        ...
