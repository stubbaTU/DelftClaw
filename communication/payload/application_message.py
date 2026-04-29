"""Builders for outgoing ApplicationMessages and routing for inbound ones."""

from __future__ import annotations

from typing import TYPE_CHECKING

from shared.envelopes import ApplicationMessage, BTCPayload
from shared.ids import AgentId, RoomId

if TYPE_CHECKING:
    from communication.channel.inbox import Inbox


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
