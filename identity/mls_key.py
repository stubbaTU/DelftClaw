"""Signing key derived at MLS_PATH; authenticates MLS / ratchet group operations."""

from __future__ import annotations

from identity.seed import Seed
from identity.derivation import derive, MLS_PATH
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class MLSSigningKey:
    """Signature key MLS uses to authenticate group state transitions and message senders."""

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self.key = key

    @classmethod
    def from_seed(cls, seed: Seed) -> "MLSSigningKey":
        # Derive the private key at MLS_PATH and build the signing keypair.
        priv_bytes = derive(seed, MLS_PATH)
        key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        return cls(key)

    @property
    def pubkey(self) -> bytes:
        # Return the public key (algorithm-dependent length; chosen by the MLS ciphersuite).
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, data: bytes) -> bytes:
        # Sign `data` with the MLS sig key; used for MLS auth content and wire-frame signatures.
        return self.key.sign(data)
