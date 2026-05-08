"""On-wire and post-decryption envelopes shared between communication and integration."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING

import msgpack
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from shared.ids import AgentId, Epoch, Nonce, RoomId

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


WIRE_VERSION = 1


@dataclass(frozen=True)
class ApplicationMessage:
    """Application-level message body, msgpack-packed into ``WireFrame.payload``."""

    text: str
    sent_at: datetime


@dataclass(frozen=True)
class WireFrame:
    """Outermost on-wire envelope sitting just below IPv8.

    The signature covers everything in :meth:`canonical_signing_bytes` — every
    field except ``sender_signature`` itself. Receivers run ``verify(pubkey)``
    after a fresh-nonce + skew-window check on ``nonce`` / ``timestamp_ms``.
    """

    room_id: RoomId
    epoch: Epoch
    sender: AgentId
    msg_type: int
    nonce: Nonce
    timestamp_ms: int
    payload: bytes
    # `payload` is canonical-msgpack ApplicationMessage bytes; no L4 encryption.
    sender_signature: bytes
    # Ed25519 signature over canonical_signing_bytes(); empty until signed.
    version: int = WIRE_VERSION

    def canonical_signing_bytes(self) -> bytes:
        """Bytes covered by ``sender_signature`` — every field except the sig itself."""
        return msgpack.packb(
            (
                self.version,
                self.msg_type,
                self.room_id.to_bytes(),
                int(self.epoch),
                self.sender.to_bytes(),
                self.nonce.to_bytes(),
                self.timestamp_ms,
                self.payload,
            ),
            use_bin_type=True,
        )

    @classmethod
    def unsigned(
        cls,
        *,
        room_id: RoomId,
        epoch: Epoch,
        sender: AgentId,
        msg_type: int,
        nonce: Nonce,
        timestamp_ms: int,
        payload: bytes,
    ) -> "WireFrame":
        return cls(
            room_id=room_id,
            epoch=epoch,
            sender=sender,
            msg_type=msg_type,
            nonce=nonce,
            timestamp_ms=timestamp_ms,
            payload=payload,
            sender_signature=b"",
        )

    def sign(self, signing_key: "Ed25519PrivateKey") -> "WireFrame":
        return replace(self, sender_signature=signing_key.sign(self.canonical_signing_bytes()))

    def verify(self, public_key: bytes) -> bool:
        if not self.sender_signature:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                self.sender_signature, self.canonical_signing_bytes()
            )
            return True
        except InvalidSignature:
            return False

    def to_bytes(self) -> bytes:
        return msgpack.packb(
            (
                self.version,
                self.msg_type,
                self.room_id.to_bytes(),
                int(self.epoch),
                self.sender.to_bytes(),
                self.nonce.to_bytes(),
                self.timestamp_ms,
                self.payload,
                self.sender_signature,
            ),
            use_bin_type=True,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "WireFrame":
        unpacked = msgpack.unpackb(data, raw=False, use_list=False)
        if not isinstance(unpacked, tuple) or len(unpacked) != 9:
            raise ValueError("WireFrame: malformed payload")
        version, msg_type, room_raw, epoch, sender_raw, nonce_raw, ts_ms, payload, sig = unpacked
        if version != WIRE_VERSION:
            raise ValueError(f"WireFrame: unsupported version {version}")
        return cls(
            room_id=RoomId(room_raw),
            epoch=Epoch(epoch),
            sender=AgentId(sender_raw),
            msg_type=int(msg_type),
            nonce=Nonce(nonce_raw),
            timestamp_ms=int(ts_ms),
            payload=bytes(payload),
            sender_signature=bytes(sig),
            version=int(version),
        )
