"""Builders for outgoing ApplicationMessages and routing for inbound ones."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import msgpack

from shared.envelopes import ApplicationMessage
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
        # Initialise empty fields.
        ...

    def with_text(self, s: str) -> "MessageBuilder":
        # Set the text body; chainable.
        ...

    def build(self) -> ApplicationMessage:
        # Validate that text is set; stamp sent_at; return frozen instance.
        ...


class PayloadRouter:
    """Inbound side: hands unpacked ApplicationMessages to the Inbox."""

    def __init__(self, inbox: "Inbox") -> None:
        # Hold the inbox queue we deliver to.
        ...

    def deliver(
        self,
        room_id: RoomId,
        sender: AgentId,
        msg: ApplicationMessage,
    ) -> None:
        # Validate payload, push onto the Inbox.
        ...
