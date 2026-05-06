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
        # Initialise empty registry.
        ...

    def add(self, room_id: RoomId, state: RoomState) -> None:
        # Insert (or replace) the room's current state.
        ...

    def state(self, room_id: RoomId) -> RoomState:
        # Look up a room's state; raise KeyError if unknown.
        ...

    def remove(self, room_id: RoomId) -> None:
        # Drop the room entry once we have left.
        ...

    def all_joined(self) -> list[RoomId]:
        # Return the RoomIds currently in JOINED state — useful for sending heartbeats.
        ...
