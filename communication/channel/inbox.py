"""Async inbox queue used by AgentChannel.recv() and PayloadRouter.deliver()."""

from __future__ import annotations

import asyncio
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
        self._q: asyncio.Queue[IncomingMessage] = asyncio.Queue(maxsize=maxsize)

    def put(self, msg: IncomingMessage) -> None:
        self._q.put_nowait(msg)

    async def get(self, timeout: float | None) -> IncomingMessage:
        if timeout is None:
            return await self._q.get()
        return await asyncio.wait_for(self._q.get(), timeout)
