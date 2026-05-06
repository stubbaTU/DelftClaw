"""Composite identity bundle: ipv8 + app-signing keys derived from one Seed."""

from __future__ import annotations

from identity.app_key import AppSigningKey
from identity.ipv8_key import IPv8KeyPair
from identity.seed import Seed
from shared.credentials import KeyBundle
from shared.ids import AgentId


class AgentIdentity:
    """Bundle of all keys an agent uses (IPv8 + app-signing); the type every other package consumes."""

    def __init__(self, ipv8: IPv8KeyPair, app: AppSigningKey) -> None:
        self._ipv8 = ipv8
        self._app = app

    @classmethod
    def from_seed(cls, seed: Seed) -> "AgentIdentity":
        """Derive ipv8 and application-signing keys at fixed paths from the master seed."""
        return cls(
            ipv8=IPv8KeyPair.from_seed(seed),
            app=AppSigningKey.from_seed(seed),
        )

    @property
    def agent_id(self) -> AgentId:
        """AgentId is the hash of the IPv8 public key."""
        return AgentId.from_pubkey(self._ipv8.pubkey)

    @property
    def ipv8(self) -> IPv8KeyPair:
        """Return the network-layer Ed25519 keypair."""
        return self._ipv8

    @property
    def app(self) -> AppSigningKey:
        """Return the application-layer Ed25519 signing key (signs WireFrames)."""
        return self._app

    def public_bundle(self) -> KeyBundle:
        """Return the pair of public keys other peers need to authenticate us."""
        return KeyBundle(
            ipv8=self._ipv8.pubkey,
            app=self._app.pubkey,
        )
