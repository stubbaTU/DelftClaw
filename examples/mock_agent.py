"""Minimal mock agent for scripted M2 testing.

Wraps an :class:`AgentChannel` plus the IPv8 plumbing in convenience methods so
demo scripts read top-down. No LLM brain — behaviour is driven by the test
script that owns the ``MockAgent`` reference and calls its async methods.
"""

from __future__ import annotations

import asyncio
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ipv8.peer import Peer

from communication.channel.agent_channel import AgentChannel
from communication.transport.ipv8_runtime import IPv8Runtime, NetworkConfig
from communication.trustroom.community import TrustroomCommunity
from communication.trustroom.policy import AdmissionPolicy
from identity.agent_identity import AgentIdentity
from identity.seed import Seed
from shared.ids import AgentId, CredentialId, RoomId
from stake import InMemoryStakeOracle, StakeProof
from trust.formats.toy import ToyEd25519Format
from trust.store import TrustStore


def raw_keypair() -> tuple[bytes, bytes]:
    """Helper to mint an Ed25519 issuer keypair (raw 32-byte private, raw 32-byte public)."""
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


class MockAgent:
    """One agent process collapsed into an async object."""

    def __init__(
        self,
        name: str,
        seed_bytes: bytes,
        port: int,
        *,
        network: str = "TESTNET",
    ) -> None:
        if len(seed_bytes) != 32:
            raise ValueError("seed must be 32 bytes")
        self.name = name
        self.port = port
        self.identity = AgentIdentity.from_seed(Seed(seed_bytes), network=network)
        self.trust_store: TrustStore = TrustStore()
        # mirror_remote=True: incoming ops from peers credit the actor's view
        # implicitly. M2 stand-in for a replicated ledger; M3 swaps in the
        # colleague's append-only log + KeyBundle PKI.
        self.oracle = InMemoryStakeOracle(mirror_remote=True)
        self.runtime = IPv8Runtime(self.identity, NetworkConfig(port=port, address="127.0.0.1"))
        self.channel = AgentChannel(
            identity=self.identity,
            runtime=self.runtime,
            trust_store=self.trust_store,
            oracle=self.oracle,
        )
        self._format = ToyEd25519Format()
        # Issuer key (a MockAgent can also act as a VC issuer for the demo).
        self._issuer_priv, self._issuer_pub = raw_keypair()

    @property
    def agent_id(self) -> AgentId:
        return self.identity.agent_id

    @property
    def issuer_pubkey(self) -> bytes:
        return self._issuer_pub

    @property
    def app_pubkey(self) -> bytes:
        return self.identity.app.pubkey

    @property
    def community(self) -> TrustroomCommunity:
        return self.channel.community

    async def start(self) -> None:
        await self.channel.start()

    async def stop(self) -> None:
        await self.channel.stop()

    # --- topology --------------------------------------------------------

    def attach_peer(self, other: "MockAgent") -> Any:
        """Make ``other`` reachable from this agent without IPv8 walker discovery."""
        peer = Peer(other.community.my_peer.public_key, address=("127.0.0.1", other.port))
        self.community.network.add_verified_peer(peer)
        self.community.network.discover_services(peer, [TrustroomCommunity.community_id])
        return peer

    # --- credentials -----------------------------------------------------

    def issue_vc(
        self,
        subject_pubkey: bytes,
        claims: dict[str, object],
    ) -> Any:
        """Issue a toy-format VC signed by this agent's local issuer key."""
        return self._format.issue(
            issuer_pubkey=self._issuer_pub,
            subject_pubkey=subject_pubkey,
            claims=claims,
            signing_key=self._issuer_priv,
        )

    def store_vc(self, vc_id: str, credential: Any) -> None:
        self.trust_store.put(CredentialId(vc_id), credential)

    # --- stake -----------------------------------------------------------

    def faucet(self, amount: int) -> None:
        """Top up this agent's local oracle (and only the local oracle) by ``amount`` sats."""
        self.oracle.faucet(self.agent_id, amount)

    def lock_for_admission(self, room_id: RoomId, amount: int) -> StakeProof:
        return self.channel.lock_for_admission(room_id, amount)

    async def broadcast_last_op(self, target: "MockAgent") -> None:
        peer = self.attach_peer(target)
        await self.channel.broadcast_last_op(peer)

    async def transfer(self, recipient: "MockAgent", amount: int) -> None:
        peer = self.attach_peer(recipient)
        await self.channel.transfer(recipient.agent_id, amount, target_peer=peer)

    def balance(self, agent: "MockAgent | AgentId | None" = None) -> int:
        target = agent.agent_id if isinstance(agent, MockAgent) else (agent or self.agent_id)
        return self.oracle.balance(target)

    # --- rooms -----------------------------------------------------------

    def create_room(self, policy: AdmissionPolicy) -> RoomId:
        return self.channel.create_room(policy)

    async def join_room(
        self,
        room_id: RoomId,
        vc_id: str,
        host: "MockAgent",
        proof: StakeProof | None = None,
    ) -> None:
        peer = self.attach_peer(host)
        await self.channel.join_room(
            room_id, CredentialId(vc_id), host_peer=peer, stake_proof=proof,
        )

    # --- messaging -------------------------------------------------------

    async def send(self, room_id: RoomId, text: str, target: "MockAgent") -> None:
        peer = self.attach_peer(target)
        await self.channel.send(room_id, text, target_peer=peer)

    async def expect_message(self, text: str, *, timeout: float = 2.0) -> None:
        msg = await self.channel.recv(timeout=timeout)
        assert msg.message.text == text, (
            f"{self.name}: expected {text!r}, got {msg.message.text!r}"
        )

    async def expect_no_message(self, *, timeout: float = 1.0) -> None:
        try:
            msg = await self.channel.recv(timeout=timeout)
            raise AssertionError(
                f"{self.name}: expected no message, got {msg.message.text!r}"
            )
        except asyncio.TimeoutError:
            return
