"""Composite identity bundle: ipv8 + mls + wallet keys derived from one Seed."""

from __future__ import annotations
import hashlib

from identity.ipv8_key import IPv8KeyPair
from identity.mls_key import MLSSigningKey
from identity.seed import Seed
from identity.wallet import Wallet
from shared.credentials import KeyBundle
from shared.ids import AgentId


class AgentIdentity:
    """Bundle of all keys an agent uses; the type every other package consumes."""

    def __init__(self, ipv8: IPv8KeyPair, mls: MLSSigningKey, wallet: Wallet) -> None:
        self._ipv8 = ipv8
        self._mls = mls
        self._wallet = wallet

    @classmethod
    def from_seed(cls, seed: Seed) -> "AgentIdentity":
        """Derive ipv8, mls, and wallet keys at fixed paths from the master seed."""
        return cls(
            ipv8=IPv8KeyPair.from_seed(seed),
            mls=MLSSigningKey.from_seed(seed),
            wallet=Wallet.from_seed(seed)
        )

    @property
    def agent_id(self) -> AgentId:
        """AgentId is derived from the raw 32-byte IPv8 public key bytes."""
        return AgentId.from_pubkey(self._ipv8.raw_pubkey)

    @property
    def ipv8(self) -> IPv8KeyPair:
        """Return the network-layer Ed25519 keypair."""
        return self._ipv8

    @property
    def mls(self) -> MLSSigningKey:
        """Return the MLS / ratchet signing key."""
        return self._mls

    @property
    def wallet(self) -> Wallet:
        """Return the Bitcoin HD wallet."""
        return self._wallet

    def public_bundle(self) -> KeyBundle:
        """Return the triple of public keys other peers need to encrypt to and authenticate us."""
        return KeyBundle(
            ipv8=self._ipv8.pubkey,
            mls=self._mls.pubkey,
            btc=self._wallet.pubkey
        )
