"""Identity-encryption backend used by tests until ADR 0003 picks an MLS library.

``MockBackend`` is *not* a security primitive. ``encrypt`` returns the plaintext
unchanged and ``decrypt`` does the same — the contract that's exercised is
membership management plus epoch advancement, so unit tests can drive the
TrustroomCommunity message path without depending on a real ratchet.
"""

from __future__ import annotations

from communication.messaging.group_state import GroupState
from communication.messaging.secure_group_session import SecureGroupSession
from identity.agent_identity import AgentIdentity
from shared.credentials import KeyBundle
from shared.errors import EpochMismatch
from shared.ids import AgentId, Epoch, RoomId


class MockBackend(SecureGroupSession):
    """Deterministic, keyless ``SecureGroupSession`` implementation for tests."""

    def __init__(self, identity: AgentIdentity, room_id: RoomId) -> None:
        self._identity = identity
        self._room_id = room_id
        self._members: list[AgentId] = [identity.agent_id]
        self._epoch = Epoch(0)

    @property
    def state(self) -> GroupState:
        return GroupState(
            epoch=self._epoch,
            members=list(self._members),
            my_index=self._members.index(self._identity.agent_id),
            root_secret=b"",
        )

    def bootstrap(self, members: list[KeyBundle]) -> bytes:
        for kb in members:
            agent = AgentId.from_pubkey(kb.ipv8)
            if agent not in self._members:
                self._members.append(agent)
        return b""

    def install_welcome(self, welcome_blob: bytes) -> None:
        return None

    def add_member(self, candidate: KeyBundle) -> bytes:
        agent = AgentId.from_pubkey(candidate.ipv8)
        if agent not in self._members:
            self._members.append(agent)
        self._epoch = Epoch(int(self._epoch) + 1)
        return b""

    def remove_member(self, agent: AgentId) -> bytes:
        if agent in self._members:
            self._members.remove(agent)
            self._epoch = Epoch(int(self._epoch) + 1)
        return b""

    def apply_commit(self, commit_blob: bytes) -> None:
        self._epoch = Epoch(int(self._epoch) + 1)

    def encrypt(self, plaintext: bytes) -> bytes:
        # Identity encryption — DO NOT ship.
        return plaintext

    def decrypt(self, ciphertext: bytes, sender: AgentId) -> bytes:
        if sender not in self._members:
            raise EpochMismatch(f"sender {sender} not a member at epoch {int(self._epoch)}")
        return ciphertext


class MockBackendFactory:
    """Factory matching the ``SecureGroupSessionFactory`` Protocol."""

    def new(self, identity: AgentIdentity, room_id: RoomId) -> SecureGroupSession:
        return MockBackend(identity, room_id)
