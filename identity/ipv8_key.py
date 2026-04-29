"""Ed25519 keypair derived at IPV8_PATH; backs IPv8's network-layer identity."""

from __future__ import annotations

from typing import Any

from identity.seed import Seed


class IPv8KeyPair:
    """Ed25519 keypair used as the IPv8 peer identity at the network layer."""

    @classmethod
    def from_seed(cls, seed: Seed) -> "IPv8KeyPair":
        # Derive the private key at IPV8_PATH and build the Ed25519 keypair.
        ...

    @property
    def pubkey(self) -> bytes:
        # Return the 32-byte Ed25519 public key.
        ...

    def sign(self, data: bytes) -> bytes:
        # Produce an Ed25519 signature over `data`; used implicitly by IPv8 for peer auth.
        ...

    def to_ipv8_peer(self) -> Any:
        # Bridge into py-ipv8's Peer object so the runtime can register us as the local peer.
        ...
