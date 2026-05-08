"""Builders for outgoing ApplicationMessages and routing for inbound ones."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import msgpack

from shared.envelopes import ApplicationMessage
from shared.errors import PayloadInvalid
from shared.ids import AgentId, RoomId

if TYPE_CHECKING:
    from communication.channel.inbox import Inbox


def pack_application_message(msg: ApplicationMessage) -> bytes:
    """Canonical msgpack bytes carried in ``WireFrame.payload`` (no L4 encryption)."""
    return msgpack.packb(
        (msg.text, msg.sent_at.isoformat()),
        use_bin_type=True,
    )


def unpack_application_message(blob: bytes) -> ApplicationMessage:
    unpacked = msgpack.unpackb(blob, raw=False, use_list=False)
    if not isinstance(unpacked, tuple) or len(unpacked) != 2:
        raise ValueError("ApplicationMessage: malformed payload")
    text, sent_at_iso = unpacked
    return ApplicationMessage(
        text=text,
        sent_at=datetime.fromisoformat(sent_at_iso).astimezone(timezone.utc),
    )


class MessageBuilder:
    """Fluent builder used by AgentChannel to assemble an ApplicationMessage."""

    def __init__(self) -> None:
        self._text: str | None = None

    def with_text(self, s: str) -> "MessageBuilder":
        self._text = s
        return self

    def build(self) -> ApplicationMessage:
        if self._text is None:
            raise PayloadInvalid("ApplicationMessage requires a text body")
        return ApplicationMessage(
            text=self._text,
            sent_at=datetime.now(timezone.utc),
        )


class PayloadRouter:
    """Inbound side: hands unpacked ApplicationMessages to the Inbox."""

    def __init__(self, inbox: "Inbox") -> None:
        self._inbox = inbox

    def deliver(
        self,
        room_id: RoomId,
        sender: AgentId,
        msg: ApplicationMessage,
    ) -> None:
        from communication.channel.inbox import IncomingMessage

        self._inbox.put(
            IncomingMessage(
                room_id=room_id,
                sender=sender,
                message=msg,
                received_at=datetime.now(timezone.utc),
            )
        )
