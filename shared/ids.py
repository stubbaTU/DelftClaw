"""Typed primitives that flow between packages."""

from __future__ import annotations


class AgentId:
    """Typed wrapper around a peer's long-term Ed25519 public key."""

    @classmethod
    def from_pubkey(cls, pubkey: bytes) -> "AgentId":
        # Build an AgentId from raw public key bytes; reject wrong-length input.
        ...

    def __str__(self) -> str:
        # Render as a base32 short id for human-readable logs.
        ...

    def to_bytes(self) -> bytes:
        # Canonical byte serialisation used in wire frames.
        ...


class RoomId:
    """128-bit opaque identifier for a Trustroom."""

    @classmethod
    def fresh(cls) -> "RoomId":
        # Generate a cryptographically random RoomId; called by the room creator.
        ...


class MessageId:
    """128-bit per-message id, locally unique to a sending agent."""

    @classmethod
    def fresh(cls) -> "MessageId":
        # Generate a fresh random MessageId.
        ...


class Nonce:
    """96-bit anti-replay nonce used in admission and AEAD."""

    @classmethod
    def fresh(cls) -> "Nonce":
        # Generate a fresh random Nonce.
        ...


class Epoch(int):
    """MLS / ratchet epoch counter; monotonically increases per group state advance."""


class Txid(str):
    """Bitcoin txid (hex-encoded)."""


class CredentialId(str):
    """Local identifier of a Credential record stored in the TrustStore."""
