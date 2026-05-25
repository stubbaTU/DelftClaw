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
try:
    from ipv8.keyvault.private.libnaclkey import LibNaCLSK
except ModuleNotFoundError:  # py-ipv8 >= 3.2 moved legacy NaCL keys behind OpenSSL/Rust.
    from ipv8.keyvault.private.openssl import OpenSSLSK

    class LibNaCLSK(OpenSSLSK):  # type: ignore[no-redef]
        def __init__(
            self,
            key: bytes | None = None,
            *,
            binarykey: bytes | None = None,
        ) -> None:
            if binarykey is not None:
                super().__init__(binarykey)
                return
            if key is None:
                raise TypeError("LibNaCLSK requires key bytes or binarykey")
            if len(key) == 32:
                super().__init__(b"LibNaCLSK:" + key + key)
                return
            if len(key) == 64:
                super().__init__(b"LibNaCLSK:" + key)
                return
            super().__init__(key)
from ipv8.peer import Peer

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
        public = self.key.pub()
        veri = getattr(public, "veri", None)
        if veri is not None:
            return veri.vk
        public_bin = public.key_to_bin()
        if public_bin.startswith(b"LibNaCLPK:") and len(public_bin) >= 74:
            return public_bin[42:74]
        raise ValueError("unsupported IPv8 public key format")

    def sign(self, data: bytes) -> bytes:
        """Produce an Ed25519 signature over ``data``."""
        return self.key.signature(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify a signature against this keypair's public key."""
        try:
            return bool(self.key.pub().verify(signature, data))
        except Exception:
            return False

    def to_ipv8_peer(self) -> Any:
        """Bridge into py-ipv8 ``Peer`` object for runtime registration."""
        return Peer(self.key)
