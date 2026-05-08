"""End-to-end Trustroom demo (M1).

Two AgentChannels on 127.0.0.1:9091 and :9092 exercise the full join + signed-message
flow:

1. A creates a Trustroom under ``OpenClawAgentPolicy(pinned_issuer)``.
2. B presents a toy Verifiable Credential issued by the pinned issuer to B's
   AppSigningKey.
3. B is admitted; A pins B's app pubkey for that room.
4. B sends one signed ``WireFrame``-wrapped ApplicationMessage to A.
5. B replays the same WireFrame; A's NonceCache rejects it.

Run from the repo root:

    python -m examples.trustroom_demo
"""

from __future__ import annotations

# Configure logging FIRST — before any project import triggers a default config.
# Logs land in logs/trustroom_demo.jsonl (overwritten on each run); stdout still
# shows them too. Set OPENCLAW_LOG_FILE / OPENCLAW_LOG_NO_STDOUT to override.
from shared.logging import configure_logging  # noqa: E402

configure_logging(log_file="logs/trustroom_demo.jsonl")

import asyncio  # noqa: E402
import time  # noqa: E402
from typing import Any  # noqa: E402

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ipv8.peer import Peer

from communication.channel.agent_channel import AgentChannel
from communication.payload.application_message import pack_application_message
from communication.transport.ipv8_runtime import IPv8Runtime, NetworkConfig
from communication.trustroom.community import TrustroomCommunity
from communication.trustroom.policy import OpenClawAgentPolicy
from identity.agent_identity import AgentIdentity
from identity.seed import Seed
from shared.envelopes import ApplicationMessage, WireFrame
from shared.ids import CredentialId, Epoch, Nonce
from trust.formats.toy import ToyEd25519Format
from trust.store import TrustStore


def _raw_keypair() -> tuple[bytes, bytes]:
    """Return (raw 32-byte private, raw 32-byte public) for a fresh Ed25519 keypair."""
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


def _attach(comm_local: TrustroomCommunity, comm_remote: TrustroomCommunity, port: int) -> Any:
    """Tell ``comm_local`` about ``comm_remote`` without a discovery walker."""
    peer = Peer(comm_remote.my_peer.public_key, address=("127.0.0.1", port))
    comm_local.network.add_verified_peer(peer)
    comm_local.network.discover_services(peer, [TrustroomCommunity.community_id])
    return peer


async def main() -> None:
    issuer_priv, issuer_pub = _raw_keypair()

    seed_a = Seed(b"\x01" * 32)
    seed_b = Seed(b"\x02" * 32)
    ident_a = AgentIdentity.from_seed(seed_a)
    ident_b = AgentIdentity.from_seed(seed_b)

    runtime_a = IPv8Runtime(ident_a, NetworkConfig(port=9091, address="127.0.0.1"))
    runtime_b = IPv8Runtime(ident_b, NetworkConfig(port=9092, address="127.0.0.1"))

    store_a: TrustStore = TrustStore()
    store_b: TrustStore = TrustStore()

    fmt = ToyEd25519Format()
    cred = fmt.issue(
        issuer_pubkey=issuer_pub,
        subject_pubkey=ident_b.app.pubkey,
        claims={"role": "agent", "agent": "B"},
        signing_key=issuer_priv,
    )
    store_b.put(CredentialId("dev-vc"), cred)

    channel_a = AgentChannel(ident_a, runtime_a, store_a)
    channel_b = AgentChannel(ident_b, runtime_b, store_b)

    await channel_a.start()
    await channel_b.start()
    try:
        comm_a = channel_a.community
        comm_b = channel_b.community

        peer_b_from_a = _attach(comm_a, comm_b, port=9092)
        peer_a_from_b = _attach(comm_b, comm_a, port=9091)
        print(f"A mid: {comm_a.my_peer.mid.hex()[:16]}  B mid: {comm_b.my_peer.mid.hex()[:16]}")
        print(f"A agent_id: {ident_a.agent_id}")
        print(f"B agent_id: {ident_b.agent_id}")

        # 1. A creates a room.
        room_id = channel_a.create_room(OpenClawAgentPolicy(issuer_pub))
        print(f"\n[1] A created room {room_id}")

        # 2-3. B joins by presenting the VC.
        await channel_b.join_room(room_id, CredentialId("dev-vc"), host_peer=peer_a_from_b)
        print(f"[2-3] B was admitted into the room")
        print(f"      A's view of members: {[str(m) for m in channel_a.members(room_id)]}")

        # 4. B sends one message via AgentChannel.send.
        await channel_b.send(room_id, "hello from B", target_peer=peer_a_from_b)
        try:
            incoming = await channel_a.recv(timeout=2.0)
            assert incoming.message.text == "hello from B"
            print(f"[4] A received: {incoming.message.text!r} from {incoming.sender}")
        except asyncio.TimeoutError:
            print("[4] FAILED — A timed out waiting for B's first message")
            raise

        # 5. Build a fresh signed WireFrame, send it twice. The second arrival
        #    must be rejected by the NonceCache.
        replay_msg = ApplicationMessage(text="replay me", sent_at=incoming.received_at)
        replay_frame = WireFrame.unsigned(
            room_id=room_id,
            epoch=Epoch(0),
            sender=ident_b.agent_id,
            msg_type=int(TrustroomCommunity.MsgId.APPLICATION),
            nonce=Nonce.fresh(),
            timestamp_ms=int(time.time() * 1000),
            payload=pack_application_message(replay_msg),
        ).sign(ident_b.app.key)
        replay_bytes = replay_frame.to_bytes()

        await comm_b.send_application(peer_a_from_b, replay_bytes)
        try:
            first = await channel_a.recv(timeout=2.0)
            print(f"[5a] First copy delivered: {first.message.text!r}")
        except asyncio.TimeoutError:
            print("[5a] FAILED — first copy never arrived")
            raise

        await comm_b.send_application(peer_a_from_b, replay_bytes)
        try:
            second = await channel_a.recv(timeout=1.0)
            print(f"[5b] FAILED — replayed frame was accepted: {second.message.text!r}")
        except asyncio.TimeoutError:
            print("[5b] OK — replayed WireFrame was rejected by NonceCache")

        print("\nM1 demo complete.")
    finally:
        await channel_a.stop()
        await channel_b.stop()


if __name__ == "__main__":
    asyncio.run(main())
