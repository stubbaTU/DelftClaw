"""Composite identity bundle: ipv8 + mls + wallet keys derived from one Seed."""

from __future__ import annotations

from identity.ipv8_key import IPv8KeyPair
from identity.mls_key import MLSSigningKey
from identity.seed import Seed
from identity.wallet import Wallet
from shared.credentials import KeyBundle
from shared.ids import AgentId


class AgentIdentity:
    """Bundle of all keys an agent uses; the type every other package consumes."""

    @classmethod
    def from_seed(cls, seed: Seed) -> "AgentIdentity":
        # Derive ipv8, mls, and wallet keys at fixed paths from the master seed.
        ...

    @property
    def agent_id(self) -> AgentId:
        # AgentId is the hash of the IPv8 public key.
        ...

    @property
    def ipv8(self) -> IPv8KeyPair:
        # Return the network-layer Ed25519 keypair.
        ...

    @property
    def mls(self) -> MLSSigningKey:
        # Return the MLS / ratchet signing key.
        ...

    @property
    def wallet(self) -> Wallet:
        # Return the Bitcoin HD wallet.
        ...

    def public_bundle(self) -> KeyBundle:
        # Return the triple of public keys other peers need to encrypt to and authenticate us.
        ...
