"""The master 32-byte seed and the strategies that load it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Seed:
    """The master 32-byte seed. Treat the contents as cryptographic secret material."""

    bytes: bytes


class SeedSource(Protocol):
    """Strategy interface for producing a Seed from some persistent location."""

    def load(self) -> Seed:
        # Produce a Seed from whatever source this implementation knows about.
        ...


class MnemonicSeedSource(SeedSource):
    """Derive a Seed from a BIP-39 mnemonic phrase (with optional passphrase)."""

    def __init__(self, mnemonic: str, passphrase: str = "") -> None:
        # Store the mnemonic and passphrase; do not derive yet.
        ...

    def load(self) -> Seed:
        # Run BIP-39 PBKDF2 to derive the 64-byte seed; truncate / hash to the 32-byte Seed.
        ...


class EnvSeedSource(SeedSource):
    """Read a hex-encoded seed from the OPENCLAW_SEED env var. Dev-only."""

    def load(self) -> Seed:
        # Read OPENCLAW_SEED, hex-decode, raise IdentityError if absent or malformed.
        ...


class KeyringSeedSource(SeedSource):
    """Read the seed from the OS keyring (secret-service / Keychain). Production path."""

    def __init__(self, service: str, account: str) -> None:
        # Store the keyring lookup parameters.
        ...

    def load(self) -> Seed:
        # Look up the secret in the OS keyring; raise IdentityError on missing entry.
        ...
