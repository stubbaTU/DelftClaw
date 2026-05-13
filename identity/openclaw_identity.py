from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


class _IPv8IdentityAdapter:
    def __init__(self, private_key: Ed25519PrivateKey):
        self.key = private_key
        self.pubkey = private_key.public_key()
        self.raw_pubkey = self.pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data)


class OpenClawIdentity:
    """Persistent OpenClaw identity bound to SHA256(public_key|network)."""

    def __init__(self, network: str = "MAINNET", key_path: str | Path | None = None):
        self.network = network.upper()
        self.key_path = Path(key_path or ".openclaw_identity_key")
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._private_key = self._load_or_create_private_key()
        self.ipv8 = _IPv8IdentityAdapter(self._private_key)
        self.public_key = self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.serialized_public_key = self.public_key
        self.identity_hash_bytes = hashlib.sha256(self.public_key + self.network.encode("utf-8")).digest()
        self.identity_hash = self.identity_hash_bytes.hex()

    def get_identity_hash(self) -> str:
        return self.identity_hash

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    @staticmethod
    def identity_hash_for_public_key(public_key: bytes, network: str = "MAINNET") -> str:
        return hashlib.sha256(public_key + network.upper().encode("utf-8")).hexdigest()

    def _load_or_create_private_key(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            raw = self.key_path.read_text(encoding="utf-8").strip()
            try:
                private_bytes = bytes.fromhex(raw)
            except ValueError as exc:
                raise ValueError(f"invalid OpenClaw identity key at {self.key_path}") from exc
            if len(private_bytes) != 32:
                raise ValueError(f"invalid OpenClaw identity key at {self.key_path}: expected 32 bytes")
            return Ed25519PrivateKey.from_private_bytes(private_bytes)

        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption(),
        )
        self.key_path.write_text(private_bytes.hex(), encoding="utf-8")
        return private_key
