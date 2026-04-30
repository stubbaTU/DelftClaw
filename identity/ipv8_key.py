"""Ed25519 keypair derived at IPV8_PATH; backs IPv8's network-layer identity."""

from __future__ import annotations

from typing import Any
import sys
import os

if sys.platform == "win32":
    _root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    _lib_path = os.path.join(_root, "libsodium", "libsodium", "x64", "Release", "v143", "dynamic")
    if os.path.exists(_lib_path):
        os.add_dll_directory(_lib_path)

from ipv8.keyvault.private.libnaclkey import LibNaCLSK
from ipv8.peer import Peer

from identity.seed import Seed
from identity.derivation import derive, IPV8_PATH


class IPv8KeyPair:
    """Ed25519 keypair used as the IPv8 peer identity at the network layer."""

    def __init__(self, key: Any) -> None:
        self.key = key

    @classmethod
    def from_seed(cls, seed: Seed) -> "IPv8KeyPair":
        # Derive the private key at IPV8_PATH and build the Ed25519 keypair.
        priv_bytes = derive(seed, IPV8_PATH)

        # LibNaClSK requires a private key bytes in some versions, but can parse from binary
        # Notice that in LibNaCLSK, binarykey is expected to be crypt + seed
        return cls(LibNaCLSK(priv_bytes))

    @property
    def pubkey(self) -> bytes:
        # Return the 32-byte Ed25519 public key.
        return self.key.pub().key_to_bin()

    def sign(self, data: bytes) -> bytes:
        # Produce an Ed25519 signature over `data`; used implicitly by IPv8 for peer auth.
        return self.key.sign(data)

    def to_ipv8_peer(self) -> Any:
        # Bridge into py-ipv8's Peer object so the runtime can register us as the local peer.
        peer = Peer(self.key)
        return peer
