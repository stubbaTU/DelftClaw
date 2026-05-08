"""BIP-32 derivation paths and the derive() helper."""

from __future__ import annotations

from identity.seed import Seed
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
APP_PATH = DerivationPath("m/44'/0'/0'/1/0")
"""`APP_PATH` derives the Ed25519 key used for application-layer WireFrame signatures."""
WALLET_PATH = DerivationPath("m/44'/0'/0'/2/0")
"""`WALLET_PATH` derives the Ed25519 key used for synthetic-BTC ``StakeOp`` signatures."""


def derive(seed: Seed, path: DerivationPath) -> bytes:
    """Standard BIP-32 child-key derivation; returns a 32-byte private key for the given path."""
    from bip_utils import Bip32Ed25519Kholaw

    # Khovratovich derivation supports non-hardened indices, unlike SLIP-10 BIP-32 for Ed25519.
    bip32_ctx = Bip32Ed25519Kholaw.FromSeed(seed.bytes)
    derived_ctx = bip32_ctx.DerivePath(str(path))
    return derived_ctx.PrivateKey().Raw().ToBytes()
