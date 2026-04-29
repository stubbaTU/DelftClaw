"""Async inbox queue used by AgentChannel.recv() and PayloadRouter.deliver()."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from shared.envelopes import ApplicationMessage
from shared.ids import AgentId, RoomId


@dataclass(frozen=True)
class IncomingMessage:
    """One delivered message, surfaced to the LLM via AgentChannel.recv."""

    room_id: RoomId
    sender: AgentId
    message: ApplicationMessage
    received_at: datetime


class Inbox:
    """Bounded asyncio queue with synchronous put for non-async producers."""

    def __init__(self, maxsize: int = 1024) -> None:
        # Build the underlying asyncio.Queue; cap to prevent unbounded buffering.
        ...

    def put(self, msg: IncomingMessage) -> None:
        # Synchronous push from PayloadRouter; raise QueueFull on overflow.
        ...

    async def get(self, timeout: float | None) -> IncomingMessage:
        # Wait for the next IncomingMessage; raise asyncio.TimeoutError on timeout.
        ...
