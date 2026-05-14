"""Per-room admitted-membership pin store consumed by the receive path."""

from __future__ import annotations

from dataclasses import dataclass, field

from shared.ids import AgentId, RoomId


@dataclass
class _RoomEntry:
    host: AgentId
    host_app_pubkey: bytes
    policy_descriptor: str
    members: dict[AgentId, bytes] = field(default_factory=dict)
    # ``members`` maps AgentId → app_pubkey. Always contains the host.


class TrustroomState:
    """Tracks which (room, agent) pairs are admitted, and which app pubkey to verify against.

    On the host side this is populated by ``TrustroomCommunity.on_join_request`` after a
    positive ``AdmissionGate.evaluate``. On the joiner side, M1 records only the host
    (post-membership broadcasts to other members come in M2).
    """

    def __init__(self) -> None:
        self._rooms: dict[RoomId, _RoomEntry] = {}

    def create(
        self,
        room_id: RoomId,
        host: AgentId,
        host_app_pubkey: bytes,
        policy_descriptor: str,
    ) -> None:
        entry = _RoomEntry(
            host=host,
            host_app_pubkey=bytes(host_app_pubkey),
            policy_descriptor=policy_descriptor,
        )
        entry.members[host] = bytes(host_app_pubkey)
        self._rooms[room_id] = entry

    def admit(self, room_id: RoomId, member: AgentId, app_pubkey: bytes) -> None:
        entry = self._rooms.get(room_id)
        if entry is None:
            raise KeyError(f"room {room_id!s} not created on this node")
        entry.members[member] = bytes(app_pubkey)

    def is_member(self, room_id: RoomId, agent_id: AgentId) -> bool:
        entry = self._rooms.get(room_id)
        return entry is not None and agent_id in entry.members

    def app_pubkey(self, room_id: RoomId, agent_id: AgentId) -> bytes:
        return self._rooms[room_id].members[agent_id]

    def members(self, room_id: RoomId) -> list[AgentId]:
        entry = self._rooms.get(room_id)
        return list(entry.members) if entry else []

    def host(self, room_id: RoomId) -> AgentId:
        return self._rooms[room_id].host

    def remove(self, room_id: RoomId) -> None:
        self._rooms.pop(room_id, None)

    def __contains__(self, room_id: RoomId) -> bool:
        return room_id in self._rooms
