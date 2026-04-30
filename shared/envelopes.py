"""On-wire and post-decryption envelopes shared between communication and integration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from shared.ids import AgentId, Epoch, RoomId


@dataclass(frozen=True)
class BTCPayload:
    """The Layer 5 Bitcoin payload carried inside an ApplicationMessage."""

    amount_sats: int
    recipient_btc_pubkey: bytes
    signed_tx: bytes
    # `signed_tx` is already signed by the sender's BIP-32 BTC key; receiver must verify.


@dataclass(frozen=True)
class ApplicationMessage:
    """Plaintext payload visible after Layer 4 decryption."""

    text: str
    payment: BTCPayload | None
    intent_attestation: bytes | None
    # `intent_attestation` is the SQ4 hook: a signed digest of the producing prompt.
    sent_at: datetime


@dataclass(frozen=True)
class WireFrame:
    """Outermost on-wire envelope sitting just below IPv8."""

    room_id: RoomId
    epoch: Epoch
    sender: AgentId
    ciphertext: bytes
    # `ciphertext` is an MLS PrivateMessage (Path A) or ratchet ciphertext (Path B).
    sender_signature: bytes
    # `sender_signature` is produced with the sender's MLS sig key; binds frame to sender within epoch.
