"""The master 32-byte seed and the strategies that load it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
import os
import hashlib


@dataclass(frozen=True)
class Seed:
    """The master 32-byte seed. Treat the contents as cryptographic secret material."""

    bytes: bytes


class SeedSource(Protocol):
    """Strategy interface for producing a Seed from some persistent location."""

    def load(self) -> Seed:
        """Produce a Seed from whatever source this implementation knows about."""
        ...


class MnemonicSeedSource(SeedSource):
    """Derive a Seed from a BIP-39 mnemonic phrase (with optional passphrase)."""

    def __init__(self, mnemonic: str, passphrase: str = "") -> None:
        """Store the mnemonic and passphrase; do not derive yet."""
        self.mnemonic = mnemonic
        self.passphrase = passphrase

    def load(self) -> Seed:
        """Run BIP-39 PBKDF2 to derive the 64-byte seed; truncate / hash to the 32-byte Seed."""
        from bip_utils import Bip39SeedGenerator
        # Derive 64-byte seed
        bip39_seed = Bip39SeedGenerator(self.mnemonic).Generate(self.passphrase)
        # Convert to 32 bytes (we will use sha256 to fold it)
        truncated = hashlib.sha256(bip39_seed).digest()
        return Seed(truncated)


class EnvSeedSource(SeedSource):
    """Read a hex-encoded seed from the OPENCLAW_SEED env var. Dev-only."""

    def load(self) -> Seed:
        """Read OPENCLAW_SEED, hex-decode, raise ValueError if absent or malformed."""
        seed_hex = os.environ.get("OPENCLAW_SEED")
        if not seed_hex:
            raise ValueError("OPENCLAW_SEED environment variable is not set")
        try:
            seed_bytes = bytes.fromhex(seed_hex)
        except ValueError:
            raise ValueError("OPENCLAW_SEED must be valid hex")

        if len(seed_bytes) != 32:
            raise ValueError("OPENCLAW_SEED must be exactly 32 bytes when hex-decoded")

        return Seed(seed_bytes)


class KeyringSeedSource(SeedSource):
    """Read the seed from the OS keyring (secret-service / Keychain). Production path."""

    def __init__(self, service: str, account: str) -> None:
        """Store the keyring lookup parameters."""
        self.service = service
        self.account = account

    def load(self) -> Seed:
        """Look up the secret in the OS keyring; raise ValueError on missing entry."""
        import keyring
        secret_hex = keyring.get_password(self.service, self.account)
        if not secret_hex:
            raise ValueError("Seed not found in keyring")

        try:
            return Seed(bytes.fromhex(secret_hex))
        except ValueError:
            raise ValueError("Seed in keyring must be valid hex")
