"""Builders for outgoing ApplicationMessages and routing for inbound ones."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import msgpack

from shared.envelopes import ApplicationMessage, BTCPayload
from shared.ids import AgentId, RoomId

if TYPE_CHECKING:
    from communication.channel.inbox import Inbox


def pack_application_message(msg: ApplicationMessage) -> bytes:
    """Canonical msgpack bytes — the input that SecureGroupSession.encrypt receives."""
    payment_tuple = (
        (msg.payment.amount_sats, msg.payment.recipient_btc_pubkey, msg.payment.signed_tx)
        if msg.payment is not None
        else None
    )
    return msgpack.packb(
        (msg.text, payment_tuple, msg.intent_attestation, msg.sent_at.isoformat()),
        use_bin_type=True,
    )


def unpack_application_message(blob: bytes) -> ApplicationMessage:
    unpacked = msgpack.unpackb(blob, raw=False, use_list=False)
    if not isinstance(unpacked, tuple) or len(unpacked) != 4:
        raise ValueError("ApplicationMessage: malformed payload")
    text, payment_raw, intent_attestation, sent_at_iso = unpacked
    payment = (
        BTCPayload(
            amount_sats=int(payment_raw[0]),
            recipient_btc_pubkey=bytes(payment_raw[1]),
            signed_tx=bytes(payment_raw[2]),
        )
        if payment_raw is not None
        else None
    )
    return ApplicationMessage(
        text=text,
        payment=payment,
        intent_attestation=bytes(intent_attestation) if intent_attestation is not None else None,
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

    def with_payment(self, p: BTCPayload) -> "MessageBuilder":
        # Attach a BTCPayload; chainable.
        ...

    def with_intent_attestation(self, blob: bytes) -> "MessageBuilder":
        # Attach a signed digest of the producing prompt (SQ4 mechanism hook); chainable.
        ...

    def build(self) -> ApplicationMessage:
        # Validate that at least one of {text, payment} is set; stamp sent_at; return frozen instance.
        ...


class PayloadRouter:
    """Inbound side: hands decrypted ApplicationMessages to the Inbox."""

    def __init__(self, inbox: "Inbox") -> None:
        # Hold the inbox queue we deliver to.
        ...

    def deliver(
        self,
        room_id: RoomId,
        sender: AgentId,
        msg: ApplicationMessage,
    ) -> None:
        # Validate payload, run any payment-side effects (e.g. PaymentVerifier), push onto the Inbox.
        ...
