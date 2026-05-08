"""Synthetic-BTC wallet keyed off Ed25519 at WALLET_PATH.

Balance state lives in ``stake.StakeOracle``, not on the wallet itself. The
wallet object holds only the signing key — restart-safe, no balance recovery.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.derivation import WALLET_PATH, derive
from identity.seed import Seed


class Wallet:
    """Ed25519 signing key derived at WALLET_PATH; signs synthetic ``StakeOp`` ops."""

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self.key = key

    @classmethod
    def from_seed(cls, seed: Seed) -> "Wallet":
        priv_bytes = derive(seed, WALLET_PATH)
        if len(priv_bytes) == 64:
            priv_bytes = priv_bytes[:32]
        return cls(Ed25519PrivateKey.from_private_bytes(priv_bytes))

    @property
    def pubkey(self) -> bytes:
        """Return the canonical 32-byte Ed25519 verify key."""
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, data: bytes) -> bytes:
        """Produce an Ed25519 signature; used by ``StakeOp.sign``."""
        return self.key.sign(data)
