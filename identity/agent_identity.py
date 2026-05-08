"""Composite identity bundle: ipv8 + app-signing + wallet keys derived from one Seed."""

from __future__ import annotations

import hashlib

from identity.app_key import AppSigningKey
from identity.ipv8_key import IPv8KeyPair
from identity.seed import Seed
from identity.wallet import Wallet
from shared.credentials import KeyBundle
from shared.ids import AgentId, IdentityHash


def _normalize_network(value: str) -> str:
    cleaned = value.strip().upper()
    if not cleaned:
        raise ValueError("network must not be empty")
    return cleaned


class AgentIdentity:
    """Bundle of all keys an agent uses (IPv8 + app-signing + wallet); the type every other package consumes."""

    def __init__(
        self,
        ipv8: IPv8KeyPair,
        app: AppSigningKey,
        wallet: Wallet,
        network: str = "TESTNET",
    ) -> None:
        self._ipv8 = ipv8
        self._app = app
        self._wallet = wallet
        self._network = _normalize_network(network)

    @classmethod
    def from_seed(cls, seed: Seed, network: str = "TESTNET") -> "AgentIdentity":
        """Derive ipv8, application-signing, and wallet keys at fixed paths from the master seed."""
        return cls(
            ipv8=IPv8KeyPair.from_seed(seed),
            app=AppSigningKey.from_seed(seed),
            wallet=Wallet.from_seed(seed),
            network=network,
        )

    @property
    def agent_id(self) -> AgentId:
        """AgentId is derived from the raw 32-byte IPv8 public key bytes."""
        return AgentId.from_pubkey(self._ipv8.raw_pubkey)

    @property
    def network(self) -> str:
        """The network label this identity is bound to (e.g. ``MAINNET``, ``TESTNET``)."""
        return self._network

    @property
    def network_hash(self) -> IdentityHash:
        """SHA256(IPv8_raw_pubkey || network) — a network-bound 32-byte digest."""
        digest = hashlib.sha256(self._ipv8.raw_pubkey + self._network.encode("utf-8")).digest()
        return IdentityHash.from_bytes(digest)

    @property
    def ipv8(self) -> IPv8KeyPair:
        """Return the network-layer Ed25519 keypair."""
        return self._ipv8

    @property
    def app(self) -> AppSigningKey:
        """Return the application-layer Ed25519 signing key (signs WireFrames)."""
        return self._app

    @property
    def wallet(self) -> Wallet:
        """Return the synthetic-BTC Ed25519 signing key (signs StakeOps)."""
        return self._wallet

    def public_bundle(self) -> KeyBundle:
        """Return the triple of public keys other peers need to authenticate us."""
        return KeyBundle(
            ipv8=self._ipv8.pubkey,
            app=self._app.pubkey,
            wallet=self._wallet.pubkey,
        )
