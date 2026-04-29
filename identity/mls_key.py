"""Signing key derived at MLS_PATH; authenticates MLS / ratchet group operations."""

from __future__ import annotations

from identity.seed import Seed


class MLSSigningKey:
    """Signature key MLS uses to authenticate group state transitions and message senders."""

    @classmethod
    def from_seed(cls, seed: Seed) -> "MLSSigningKey":
        # Derive the private key at MLS_PATH and build the signing keypair.
        ...

    @property
    def pubkey(self) -> bytes:
        # Return the public key (algorithm-dependent length; chosen by the MLS ciphersuite).
        ...

    def sign(self, data: bytes) -> bytes:
        # Sign `data` with the MLS sig key; used for MLS auth content and wire-frame signatures.
        ...
