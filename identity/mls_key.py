"""MLS signing key primitive for OpenClaw agents."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from identity.derivation import APP_PATH, derive
from identity.seed import Seed


class MLSSigningKey:
    """Ed25519 signing key used for MLS key package authentication."""

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self.key = key

    @classmethod
    def from_seed(cls, seed: Seed) -> "MLSSigningKey":
        """Derive deterministic MLS signing key from APP_PATH."""
        priv_bytes = derive(seed, APP_PATH)
        if len(priv_bytes) > 32:
            priv_bytes = priv_bytes[:32]
        return cls(Ed25519PrivateKey.from_private_bytes(priv_bytes))

    @classmethod
    def generate(cls) -> "MLSSigningKey":
        """Generate a fresh random MLS signing key."""
        return cls(Ed25519PrivateKey.generate())

    @property
    def public_key_bytes(self) -> bytes:
        """Return raw 32-byte Ed25519 public key bytes."""
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, msg: bytes) -> bytes:
        """Sign bytes with MLS private key."""
        return self.key.sign(msg)

    def verify(self, msg: bytes, sig: bytes) -> bool:
        """Verify bytes/signature pair against MLS public key."""
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key_bytes).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False

    def key_package(self) -> dict[str, str]:
        """Return minimal MLS-compatible key package metadata."""
        return {
            "suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "public_key": self.public_key_bytes.hex(),
            "signature_scheme": "Ed25519",
        }

