"""OpenClaw-specific identity wrapper: local IPv8 key file + network-bound hash."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Any

if sys.platform == "win32":
    _root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if os.path.exists(os.path.join(_root, "libsodium.dll")):
        os.add_dll_directory(_root)

from ipv8.keyvault.private.libnaclkey import LibNaCLSK

from identity.ipv8_key import IPv8KeyPair
from shared.ids import IdentityHash

_LIBNACL_SK_PREFIX = b"LibNaCLSK:"


def _default_key_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "OpenClaw" / "identity" / "openclaw_priv.pem"
    return Path.home() / ".openclaw" / "identity" / "openclaw_priv.pem"


class OpenClawIdentity:
    """Local OpenClaw identity backed by one persistent IPv8 Ed25519 keypair."""

    def __init__(self, network: str = "MAINNET", key_path: str | Path | None = None) -> None:
        self.network = self._normalize_network(network)
        self.key_path = Path(key_path) if key_path is not None else _default_key_path()
        self._keypair = self._load_or_create_key()
        self._ipv8 = IPv8KeyPair(self._keypair)

    @staticmethod
    def _normalize_network(network: str) -> str:
        value = network.strip().upper()
        if not value:
            raise ValueError("network must not be empty")
        return value

    def _load_or_create_key(self) -> LibNaCLSK:
        if self.key_path.exists():
            return self._load_key()

        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        keypair = LibNaCLSK()
        self.key_path.write_text(self._secret_material(keypair).hex(), encoding="ascii")
        return keypair

    @staticmethod
    def _secret_material(keypair: LibNaCLSK) -> bytes:
        """Return the raw secret material expected by ``LibNaCLSK(binarykey=...)``."""
        serialized = keypair.key_to_bin()
        if serialized.startswith(_LIBNACL_SK_PREFIX):
            return serialized[len(_LIBNACL_SK_PREFIX):]
        return serialized

    def _load_key(self) -> LibNaCLSK:
        try:
            text = self.key_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError(f"Could not read identity key file: {self.key_path}") from exc

        if not text:
            raise ValueError(f"Identity key file is empty: {self.key_path}")

        try:
            key_bytes = bytes.fromhex(text)
            if key_bytes.startswith(_LIBNACL_SK_PREFIX):
                key_bytes = key_bytes[len(_LIBNACL_SK_PREFIX):]
            return LibNaCLSK(key_bytes)
        except Exception as exc:
            raise ValueError(f"Invalid OpenClaw identity key file: {self.key_path}") from exc

    @property
    def keypair(self) -> LibNaCLSK:
        """Return the underlying IPv8 private key object."""
        return self._keypair

    @property
    def ipv8(self) -> IPv8KeyPair:
        """Return the IPv8-friendly wrapper around the same keypair."""
        return self._ipv8

    @property
    def public_key(self) -> bytes:
        """Return the canonical 32-byte Ed25519 verify key."""
        return self._ipv8.raw_pubkey

    @property
    def serialized_public_key(self) -> bytes:
        """Return the serialized IPv8 public key form used by `py-ipv8`."""
        return self._ipv8.pubkey

    @property
    def identity_hash(self) -> IdentityHash:
        """Return SHA256(IPv8_Public_Key | NETWORK) as a typed 32-byte digest."""
        return IdentityHash.from_bytes(self.identity_hash_bytes)

    @property
    def identity_hash_bytes(self) -> bytes:
        """Return the raw SHA-256 digest used to identify the OpenClaw node."""
        payload = self.public_key + self.network.encode("utf-8")
        return hashlib.sha256(payload).digest()

    def get_identity_hash(self) -> str:
        """Return the identity hash as a hex string."""
        return str(self.identity_hash)

    def sign(self, data: bytes) -> bytes:
        """Sign `data` with the local IPv8 private key."""
        return self._keypair.signature(data)

    def to_ipv8_peer(self) -> Any:
        """Bridge into py-ipv8's Peer object."""
        return self._ipv8.to_ipv8_peer()



