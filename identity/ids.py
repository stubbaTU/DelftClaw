"""Typed primitives that flow between packages."""

from __future__ import annotations

import base64


class _RawBytes:
    __slots__ = ("_raw",)
    _SIZE: int = 0

    def __init__(self, raw: bytes) -> None:
        if len(raw) != self._SIZE:
            raise ValueError(f"{type(self).__name__} expects {self._SIZE} bytes, got {len(raw)}")
        object.__setattr__(self, "_raw", bytes(raw))

    def __bytes__(self) -> bytes:
        return self._raw

    def __eq__(self, other: object) -> bool:
        return type(self) is type(other) and self._raw == other._raw  # type: ignore[attr-defined]

    def __hash__(self) -> int:
        return hash((type(self).__name__, self._raw))


class AgentId(_RawBytes):
    """Typed wrapper around a peer's long-term Ed25519 public key."""
    _SIZE = 32

    @classmethod
    def from_pubkey(cls, pubkey: bytes) -> "AgentId":
        return cls(pubkey)

    def __str__(self) -> str:
        return base64.b32encode(self._raw[:10]).decode("ascii").rstrip("=").lower()


class IdentityHash(_RawBytes):
    """32-byte SHA-256 digest binding a public key to a network name."""
    _SIZE = 32

    def __str__(self) -> str:
        return self._raw.hex()
