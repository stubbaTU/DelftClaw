"""Ed25519 identity adapter.

Local replacement for DelftClaw's ``identity.openclaw_identity.OpenClawIdentity``.
The vendored ``signed_log.py`` depends only on the following surface of an
identity object, all of which are provided here:

    * ``public_key``  -> 32 raw bytes (Ed25519 verify key)
    * ``network``     -> str (used in the identity-binding hash + witness checks)
    * ``sign(data: bytes) -> bytes`` -> raw 64-byte Ed25519 signature

A ``reporter_id`` property (``sha256(public_key + network.encode()).hexdigest()``)
is also exposed so callers can derive the binding identifier the log embeds.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


class Ed25519Identity:
    """Minimal Ed25519 identity satisfying the signed-log identity port."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey | None = None,
        network: str = "MAINNET",
    ) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()
        self.network = network

    @property
    def public_key(self) -> bytes:
        """Return the 32-byte raw Ed25519 public key."""
        return self._private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    def sign(self, data: bytes) -> bytes:
        """Return the raw 64-byte Ed25519 signature over ``data``."""
        return self._private_key.sign(data)

    @property
    def reporter_id(self) -> str:
        """SHA-256 of ``public_key || network`` as hex (identity binding)."""
        return hashlib.sha256(
            self.public_key + self.network.encode("utf-8")
        ).hexdigest()

    def verify(self, signature: bytes, data: bytes) -> None:
        """Verify ``signature`` over ``data``; raises on failure."""
        Ed25519PublicKey.from_public_bytes(self.public_key).verify(
            signature, data
        )
