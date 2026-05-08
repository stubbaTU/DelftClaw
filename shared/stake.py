"""``StakeOp`` — the authenticated record of a synthetic-BTC operation.

Same shape as :class:`shared.envelopes.WireFrame`: a frozen dataclass with
``canonical_signing_bytes`` / ``sign`` / ``verify`` / ``to_bytes`` / ``from_bytes``.
Signed by the operator's :class:`identity.wallet.Wallet` Ed25519 key.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

import msgpack
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from shared.errors import PayloadInvalid
from shared.ids import AgentId, Nonce

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


_NULL_AGENT = b"\x00" * 32


class StakeOpKind(StrEnum):
    """The four operations recognised in M2. ``SLASH`` is deferred to M3."""

    MINT = "mint"
    TRANSFER = "transfer"
    LOCK = "lock"
    UNLOCK = "unlock"


@dataclass(frozen=True)
class StakeOp:
    """One signed synthetic-BTC operation.

    ``actor`` is the operator's :class:`AgentId`. ``target`` is the recipient
    for ``TRANSFER`` and ignored otherwise. ``purpose`` is a short ASCII tag
    used by ``LOCK`` / ``UNLOCK`` to group locks (e.g. ``admission:room=<hex>``).
    """

    kind: StakeOpKind
    actor: AgentId
    target: AgentId | None
    amount: int
    purpose: str
    nonce: Nonce
    timestamp_ms: int
    signature: bytes

    def canonical_signing_bytes(self) -> bytes:
        """The bytes covered by ``signature`` — every field except the signature itself."""
        target_bytes = self.target.to_bytes() if self.target is not None else _NULL_AGENT
        return msgpack.packb(
            (
                str(self.kind),
                self.actor.to_bytes(),
                target_bytes,
                int(self.amount),
                self.purpose,
                self.nonce.to_bytes(),
                int(self.timestamp_ms),
            ),
            use_bin_type=True,
        )

    @classmethod
    def unsigned(
        cls,
        *,
        kind: StakeOpKind,
        actor: AgentId,
        target: AgentId | None,
        amount: int,
        purpose: str,
        nonce: Nonce,
        timestamp_ms: int,
    ) -> "StakeOp":
        return cls(
            kind=kind,
            actor=actor,
            target=target,
            amount=int(amount),
            purpose=purpose,
            nonce=nonce,
            timestamp_ms=int(timestamp_ms),
            signature=b"",
        )

    def sign(self, signing_key: "Ed25519PrivateKey") -> "StakeOp":
        return replace(self, signature=signing_key.sign(self.canonical_signing_bytes()))

    def verify(self, public_key: bytes) -> bool:
        if not self.signature:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                self.signature, self.canonical_signing_bytes()
            )
            return True
        except (InvalidSignature, ValueError):
            return False

    def to_bytes(self) -> bytes:
        target_bytes = self.target.to_bytes() if self.target is not None else _NULL_AGENT
        return msgpack.packb(
            (
                str(self.kind),
                self.actor.to_bytes(),
                target_bytes,
                int(self.amount),
                self.purpose,
                self.nonce.to_bytes(),
                int(self.timestamp_ms),
                self.signature,
            ),
            use_bin_type=True,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "StakeOp":
        try:
            unpacked = msgpack.unpackb(data, raw=False, use_list=False)
        except (msgpack.UnpackException, ValueError) as exc:
            raise PayloadInvalid(f"StakeOp: msgpack decode failed: {exc}") from exc
        if not isinstance(unpacked, tuple) or len(unpacked) != 8:
            raise PayloadInvalid("StakeOp: expected an 8-element tuple")
        kind_s, actor_b, target_b, amount, purpose, nonce_b, ts_ms, sig = unpacked

        try:
            kind = StakeOpKind(kind_s)
        except ValueError as exc:
            raise PayloadInvalid(f"StakeOp: unknown kind {kind_s!r}") from exc

        target_raw = bytes(target_b)
        target = None if target_raw == _NULL_AGENT else AgentId(target_raw)

        return cls(
            kind=kind,
            actor=AgentId(bytes(actor_b)),
            target=target,
            amount=int(amount),
            purpose=str(purpose),
            nonce=Nonce(bytes(nonce_b)),
            timestamp_ms=int(ts_ms),
            signature=bytes(sig),
        )
