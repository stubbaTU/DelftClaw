"""BIP-32 derivation paths and the derive() helper."""

from __future__ import annotations

from identity.seed import Seed
from bip_utils import Bip32Slip10Ed25519
import re


class DerivationPath(str):
    """Newtype wrapping a BIP-32 path string like ``m/44'/0'/0'/0/0``."""

    @classmethod
    def parse(cls, p: str) -> "DerivationPath":
        """Validate the path syntax (segments, hardened markers); raise ValueError on bad input."""
        if not re.match(r"^m(/\d+'?)+$", p):
            raise ValueError(f"Invalid derivation path schema: {p}")
        return cls(p)


# Canonical derivation paths fixed across the project. Coin-type 0 is Bitcoin per BIP-44.
IPV8_PATH = DerivationPath("m/44'/0'/0'/0/0")
MLS_PATH = DerivationPath("m/44'/0'/0'/1/0")
BTC_PATH = DerivationPath("m/84'/0'/0'/0/0")
"""`BTC_PATH` follows BIP-84 for native segwit (P2WPKH) addresses."""

REPLICA_PATH_TEMPLATE = "m/44'/0'/{replica_index}'/0/0"
"""Template used by replication.child_seed; the {replica_index} placeholder is replaced per replica."""


def derive(seed: Seed, path: DerivationPath) -> bytes:
    """Standard BIP-32 child-key derivation; returns a 32-byte private key for the given path."""
    from bip_utils import Bip32Ed25519Kholaw, Bip32Secp256k1

    # We use Khovratovich derivation for Ed25519 because standard SLIP-10 lacks non-hardened support.
    # We use Secp256k1 for Bitcoin (BIP-84, path m/84'...)
    if str(path).startswith("m/84'"):
        bip32_ctx = Bip32Secp256k1.FromSeed(seed.bytes)
    else:
        bip32_ctx = Bip32Ed25519Kholaw.FromSeed(seed.bytes)

    # Derive the provided path
    derived_ctx = bip32_ctx.DerivePath(str(path))
    return derived_ctx.PrivateKey().Raw().ToBytes()
