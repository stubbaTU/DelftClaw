"""IPv8 Ed25519 keypair wrapper used by OpenClaw identity flows."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import os
import sys

if sys.platform == "win32":
    _root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if os.path.exists(os.path.join(_root, "libsodium.dll")):
        os.add_dll_directory(_root)

from ipv8.keyvault.crypto import ECCrypto
from ipv8.keyvault.private.libnaclkey import LibNaCLSK

from identity.derivation import IPV8_PATH, derive
from identity.seed import Seed


class IPv8KeyPair:
    """Ed25519 keypair used as the IPv8 peer identity at the network layer."""

    def __init__(self, key: Any) -> None:
        self.key = key

    @classmethod
    def generate(cls) -> "IPv8KeyPair":
        """Generate a fresh IPv8 keypair using py-ipv8 ECCrypto."""
        return cls(ECCrypto().generate_key("curve25519"))

    @classmethod
    def from_seed(cls, seed: Seed) -> "IPv8KeyPair":
        """Derive deterministic private key bytes at IPV8_PATH."""
        priv_bytes = derive(seed, IPV8_PATH)
        return cls(LibNaCLSK(priv_bytes))

    @classmethod
    def load(cls, path: str | Path) -> "IPv8KeyPair":
        """Load keypair from serialized py-ipv8 private key bytes."""
        return cls(LibNaCLSK(binarykey=Path(path).read_bytes()))

    def save(self, path: str | Path) -> None:
        """Persist serialized py-ipv8 private key bytes to disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.key.key_to_bin())

    @property
    def pubkey(self) -> bytes:
        """Return serialized IPv8 public key bytes used by py-ipv8."""
        return self.key.pub().key_to_bin()

    @property
    def public_key_bytes(self) -> bytes:
        """Alias for serialized IPv8 public key bytes."""
        return self.pubkey

    @property
    def raw_pubkey(self) -> bytes:
        """Return canonical 32-byte Ed25519 verify key bytes."""
        return self.key.pub().veri.vk

    def sign(self, data: bytes) -> bytes:
        """Produce an Ed25519 signature over ``data``."""
        return self.key.signature(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature against this keypair's public key."""
        try:
            return bool(self.key.pub().verify(signature, data))
        except Exception:
            return False
