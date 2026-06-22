"""The master 32-byte seed and the strategies that load it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
import os

from bitcoinlib.mnemonic import Mnemonic


@dataclass(frozen=True)
class Seed:
    """BIP-39 derived seed bytes with optional mnemonic provenance."""

    bytes: bytes
    mnemonic: str | None = None

    @staticmethod
    def generate_mnemonic(strength: int = 128) -> str:
        """Generate a BIP-39 mnemonic phrase from entropy bits."""
        return Mnemonic().generate(strength=strength)

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "") -> "Seed":
        """Derive canonical BIP-39 seed bytes from mnemonic + passphrase."""
        return cls(bytes=Mnemonic().to_seed(mnemonic, password=passphrase), mnemonic=mnemonic)


class SeedSource(Protocol):
    """Strategy interface for producing a Seed from some persistent location."""

    def load(self) -> Seed:
        """Produce a Seed from whatever source this implementation knows about."""
        ...


class MnemonicSeedSource(SeedSource):
    """Derive a Seed from a BIP-39 mnemonic phrase (with optional passphrase)."""

    def __init__(self, mnemonic: str, passphrase: str = "") -> None:
        self.mnemonic = mnemonic
        self.passphrase = passphrase

    def load(self) -> Seed:
        """Run BIP-39 PBKDF2 and return the full seed bytes."""
        return Seed.from_mnemonic(self.mnemonic, self.passphrase)


class EnvSeedSource(SeedSource):
    """Read a hex-encoded seed from the OPENCLAW_SEED env var. Dev-only."""

    def load(self) -> Seed:
        seed_hex = os.environ.get("OPENCLAW_SEED")
        if not seed_hex:
            raise ValueError("OPENCLAW_SEED environment variable is not set")
        try:
            seed_bytes = bytes.fromhex(seed_hex)
        except ValueError as exc:
            raise ValueError("OPENCLAW_SEED must be valid hex") from exc

        if len(seed_bytes) < 16:
            raise ValueError("OPENCLAW_SEED must decode to at least 16 bytes")

        return Seed(seed_bytes)


class KeyringSeedSource(SeedSource):
    """Read the seed from the OS keyring (secret-service / Keychain)."""

    def __init__(self, service: str, account: str) -> None:
        self.service = service
        self.account = account

    def load(self) -> Seed:
        import keyring

        secret_hex = keyring.get_password(self.service, self.account)
        if not secret_hex:
            raise ValueError("Seed not found in keyring")
        try:
            return Seed(bytes.fromhex(secret_hex))
        except ValueError as exc:
            raise ValueError("Seed in keyring must be valid hex") from exc


def _default_seed_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "OpenClaw" / "identity" / "seed.txt"
    return Path.home() / ".openclaw" / "identity" / "seed.txt"


class KeyfileSeedSource(SeedSource):
    """Persist a seed source file. New files store mnemonic for portability."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else _default_seed_path()

    def load(self) -> Seed:
        if self.path.exists():
            text = self.path.read_text(encoding="utf-8").strip()
            if not text:
                raise ValueError(f"Seed file is empty: {self.path}")

            if " " in text:
                return Seed.from_mnemonic(text)

            try:
                seed_bytes = bytes.fromhex(text)
            except ValueError as exc:
                raise ValueError(f"Seed file is not valid hex: {self.path}") from exc
            if len(seed_bytes) < 16:
                raise ValueError(f"Seed file must be >=16 bytes; got {len(seed_bytes)}")
            return Seed(seed_bytes)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        mnemonic = Seed.generate_mnemonic(128)
        seed = Seed.from_mnemonic(mnemonic)
        self.path.write_text(mnemonic, encoding="ascii")
        return seed
