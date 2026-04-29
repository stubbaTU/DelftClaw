"""Path A (ADR 0003): RFC 9420 MLS wrapper.

Wraps the chosen MLS library (python-mls or OpenMLS binding — picked in week 2)
and presents the SecureGroupSession surface.
"""

from __future__ import annotations

from communication.messaging.group_state import GroupState
from communication.messaging.secure_group_session import SecureGroupSession
from identity.agent_identity import AgentIdentity
from shared.credentials import KeyBundle
from shared.ids import AgentId, RoomId


class MLSSession(SecureGroupSession):
    """RFC 9420 MLS implementation of SecureGroupSession (Path A, ADR 0003)."""

    def __init__(self, identity: AgentIdentity, room_id: RoomId, lib_handle: object) -> None:
        # Store identity, room id, and the wrapped MLS library handle.
        ...

    @property
    def state(self) -> GroupState:
        # Translate the MLS library's group state into our GroupState dataclass.
        ...

    def bootstrap(self, members: list[KeyBundle]) -> bytes:
        # Call MLS create_group, add each founder as a member, return the produced Welcome.
        ...

    def install_welcome(self, welcome_blob: bytes) -> None:
        # Hand the MLS Welcome to the library so it builds local group state.
        ...

    def add_member(self, candidate: KeyBundle) -> bytes:
        # Build an MLS Add proposal + Commit; return the framed Commit message.
        ...

    def remove_member(self, agent: AgentId) -> bytes:
        # Build an MLS Remove proposal + Commit; return the framed Commit message.
        ...

    def apply_commit(self, commit_blob: bytes) -> None:
        # Process a received MLS Commit; advances epoch via TreeKEM.
        ...

    def encrypt(self, plaintext: bytes) -> bytes:
        # MLS protect: wrap as PrivateMessage with current group keys.
        ...

    def decrypt(self, ciphertext: bytes, sender: AgentId) -> bytes:
        # MLS unprotect; raise EpochMismatch on out-of-epoch ciphertext.
        ...
