"""``StakeProof`` — a claim attached to a Presentation that the joiner has stake locked.

The proof is just an attestation, not a self-contained signature. The verifier
re-validates against its own :class:`stake.StakeOracle`; the proof's purpose
is to tell the verifier *which* lock to look up.
"""

from __future__ import annotations

from dataclasses import dataclass

import msgpack

from shared.errors import PayloadInvalid
from shared.ids import AgentId


@dataclass(frozen=True)
class StakeProof:
    """A claim that ``actor`` has at least ``min_sats`` locked under ``purpose``."""

    purpose: str
    min_sats: int
    actor: AgentId
    timestamp_ms: int

    def to_bytes(self) -> bytes:
        return msgpack.packb(
            (self.purpose, int(self.min_sats), self.actor.to_bytes(), int(self.timestamp_ms)),
            use_bin_type=True,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "StakeProof":
        try:
            unpacked = msgpack.unpackb(data, raw=False, use_list=False)
        except (msgpack.UnpackException, ValueError) as exc:
            raise PayloadInvalid(f"StakeProof: msgpack decode failed: {exc}") from exc
        if not isinstance(unpacked, tuple) or len(unpacked) != 4:
            raise PayloadInvalid("StakeProof: expected a 4-element tuple")
        purpose, min_sats, actor_b, ts = unpacked
        return cls(
            purpose=str(purpose),
            min_sats=int(min_sats),
            actor=AgentId(bytes(actor_b)),
            timestamp_ms=int(ts),
        )
