"""BIP-32 derivation paths and helpers."""

from __future__ import annotations

import re

from identity.seed import Seed


class DerivationPath(str):
    """Newtype wrapping a BIP-32 path string like ``m/44'/0'/0'/0/0``."""

    @classmethod
    def parse(cls, p: str) -> "DerivationPath":
        """Validate path syntax and return a DerivationPath instance."""
        if not re.match(r"^m(?:/\d+'?)*$", p):
            raise ValueError(f"Invalid derivation path schema: {p}")
        return cls(p)


# Canonical derivation paths fixed across the project.
IPV8_PATH = DerivationPath("m/44'/0'/0'/0/0")
APP_PATH = DerivationPath("m/44'/0'/0'/1/0")
WALLET_PATH = DerivationPath("m/44'/0'/0'/2/0")


def wallet_path(agent_index: int) -> DerivationPath:
    """Return BIP-44 payment address path for a given agent index."""
    if agent_index < 0:
        raise ValueError("agent_index must be non-negative")
    return DerivationPath.parse(f"m/44'/0'/{agent_index}'/0/0")


def derive(seed: Seed, path: DerivationPath) -> bytes:
    """BIP-32 child-key derivation returning a 32-byte private key."""
    from bip_utils import Bip32Ed25519Kholaw

    bip32_ctx = Bip32Ed25519Kholaw.FromSeed(seed.bytes)
    derived_ctx = bip32_ctx.DerivePath(str(path))
    return derived_ctx.PrivateKey().Raw().ToBytes()
