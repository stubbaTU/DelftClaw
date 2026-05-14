"""Application-layer Ed25519 signing key derived at APP_PATH.

Used to sign application-layer messages so receivers (and a future SQ2
audit log) can verify sender identity end-to-end. Independent of IPv8's
transport-layer signature, which does not survive forwarding or storage.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.derivation import APP_PATH, derive
from identity.seed import Seed


class AppSigningKey:
    """Ed25519 signing key for application-layer message signatures."""

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self.key = key

    @classmethod
    def from_seed(cls, seed: Seed) -> "AppSigningKey":
        priv_bytes = derive(seed, APP_PATH)
        if len(priv_bytes) == 64:
            priv_bytes = priv_bytes[:32]
        return cls(Ed25519PrivateKey.from_private_bytes(priv_bytes))

    @property
    def pubkey(self) -> bytes:
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data)
