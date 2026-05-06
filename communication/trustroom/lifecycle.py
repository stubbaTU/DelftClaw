"""Local registry of rooms this agent participates in, with their lifecycle state."""

from __future__ import annotations

from enum import StrEnum

from shared.ids import RoomId


class RoomState(StrEnum):
    """The lifecycle states a local room participation can be in."""

    PENDING_JOIN = "pending_join"
    JOINED = "joined"
    LEFT = "left"
    ERROR = "error"


class RoomRegistry:
    """In-memory map of RoomId → RoomState for every room this agent has touched."""

    def __init__(self) -> None:
        self._states: dict[RoomId, RoomState] = {}

    def add(self, room_id: RoomId, state: RoomState) -> None:
        self._states[room_id] = state

    def state(self, room_id: RoomId) -> RoomState:
        return self._states[room_id]

    def remove(self, room_id: RoomId) -> None:
        self._states.pop(room_id, None)

    def all_joined(self) -> list[RoomId]:
        return [rid for rid, st in self._states.items() if st == RoomState.JOINED]
