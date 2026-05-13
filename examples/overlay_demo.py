"""Phase-4 demo: ship an overlay descriptor over the wire, compile it, run it.

  1. Two IPv8 nodes (A and B) run on localhost with a ``SeedboxCommunity``
     each. They are introduced manually (no walker) so the bootstrap
     overlay is reachable both ways.
  2. Node A calls ``publish_overlay(echo_overlay.md)`` to advertise it
     and ``offer_overlay(B, md_hash)`` to tell B about it.
  3. Node B receives ``OVERLAY_OFFER``, calls ``fetch_overlay(A, md_hash)``;
     A serves ``OVERLAY_DELIVERY`` with the markdown bytes.
  4. Node B feeds the received bytes into ``OverlayRegistry.load(...)``,
     which compiles the descriptor (via the stub LLM that returns the
     hand-authored echo source) and registers the new ``GeneratedCommunity``
     with B's running IPv8 instance.
  5. Node A also loads the overlay locally so both sides have the
     ``GeneratedCommunity`` running.
  6. They exchange one ``EchoRequestPayload``/``EchoResponsePayload``
     round-trip across the new community.

This demonstrates the dynamic-protocol path end-to-end without needing a
real LLM: the stub returns the pre-recorded source for the echo
descriptor's community_id.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.community import SeedboxCommunity, overlay_id
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol import OverlayRegistry, StubLLMClient, community_id_from_md
from protocol.examples.echo_overlay_stub import ECHO_OVERLAY_SOURCE


REPO_ROOT = Path(__file__).resolve().parent.parent
ECHO_MD = (REPO_ROOT / "protocol" / "examples" / "echo_overlay.md").read_text()


def _stub_llm() -> StubLLMClient:
    cid_hex = community_id_from_md(ECHO_MD).hex()
    fenced = "```python\n" + ECHO_OVERLAY_SOURCE + "```"
    return StubLLMClient(sources={cid_hex: fenced})


def _persist_ipv8_key(identity: AgentIdentity, prefix: str) -> Path:
    """Write the agent's IPv8 private key to a tempfile so ConfigBuilder can load it."""
    tmp = tempfile.NamedTemporaryFile(prefix=prefix, suffix=".key", delete=False)
    tmp.write(identity.ipv8.key.key_to_bin())
    tmp.close()
    return Path(tmp.name)


def _build(port: int, key_path: Path) -> IPv8:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.set_address("127.0.0.1")
    builder.add_key("anchor", "curve25519", str(key_path))
    builder.add_overlay("SeedboxCommunity", "anchor", [], [], {}, [("started",)])
    return IPv8(builder.finalize(), extra_communities={"SeedboxCommunity": SeedboxCommunity})


def _seedbox(svc: IPv8) -> SeedboxCommunity:
    return next(o for o in svc.overlays if isinstance(o, SeedboxCommunity))


async def _run() -> int:
    alice = AgentIdentity.from_seed(MnemonicSeedSource(
        "army van defense carry jealous true garbage claim echo media make crunch"
    ).load(), network="TESTNET")
    bob = AgentIdentity.from_seed(MnemonicSeedSource(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).load(), network="TESTNET")

    key_a = _persist_ipv8_key(alice, "overlay_demo_alice_")
    key_b = _persist_ipv8_key(bob, "overlay_demo_bob_")

    svc_a = _build(port=8290, key_path=key_a)
    svc_b = _build(port=8291, key_path=key_b)
    await svc_a.start()
    await svc_b.start()

    try:
        sb_a = _seedbox(svc_a)
        sb_b = _seedbox(svc_b)

        # Mutual introduction (skip walker / bootstrap).
        peer_b_for_a = Peer(sb_b.my_peer.public_key, address=("127.0.0.1", 8291))
        peer_a_for_b = Peer(sb_a.my_peer.public_key, address=("127.0.0.1", 8290))
        sb_a.network.add_verified_peer(peer_b_for_a)
        sb_b.network.add_verified_peer(peer_a_for_b)

        md_hash = overlay_id(ECHO_MD)
        print(f"echo overlay md_hash: {md_hash.hex()}")

        # Both registries share the same stub LLM.
        registry_a = OverlayRegistry(svc_a, _stub_llm())
        registry_b = OverlayRegistry(svc_b, _stub_llm())

        # 1) Alice publishes the descriptor and tells Bob about it.
        sb_a.publish_overlay(ECHO_MD)
        sb_a.offer_overlay(peer_b_for_a, md_hash)

        # 2) Bob fetches the markdown over the bootstrap community.
        md_bytes_future = sb_b.fetch_overlay(peer_a_for_b, md_hash)
        md_bytes = await asyncio.wait_for(md_bytes_future, timeout=3.0)
        delivered = md_bytes.decode("utf-8")
        assert overlay_id(delivered) == md_hash, "delivered descriptor failed hash check"
        print(f"bob received {len(md_bytes)} bytes; hash matches.")

        # 3) Both compile + register the new overlay locally.
        echo_a = registry_a.load(ECHO_MD)
        echo_b = registry_b.load(delivered)
        assert echo_a.community_id == echo_b.community_id == md_hash
        print(f"both nodes registered overlay; svc_a.overlays={len(svc_a.overlays)}, svc_b.overlays={len(svc_b.overlays)}")

        # The new GeneratedCommunity has its own peer-discovery state, separate
        # from the bootstrap community. Inject the cross-peer reference there too.
        peer_b_for_a_echo = Peer(echo_b.my_peer.public_key, address=("127.0.0.1", 8291))
        peer_a_for_b_echo = Peer(echo_a.my_peer.public_key, address=("127.0.0.1", 8290))
        echo_a.network.add_verified_peer(peer_b_for_a_echo)
        echo_b.network.add_verified_peer(peer_a_for_b_echo)

        # 4) Send one ECHO_REQUEST from A to B.
        EchoRequestPayload = registry_a._compiled[md_hash].payload_classes["ECHO_REQUEST"]
        echo_a.ez_send(peer_b_for_a_echo, EchoRequestPayload(b"hello-from-a"))

        # Poll Bob's received responses.
        for _ in range(40):
            if echo_a.received_responses:
                break
            await asyncio.sleep(0.05)

        if not echo_a.received_responses:
            print("FAILED: no echo response received within 2s", file=sys.stderr)
            return 1

        print(f"echo round-trip OK: {echo_a.received_responses!r}")
        return 0
    finally:
        await svc_a.stop()
        await svc_b.stop()
        for p in (key_a, key_b):
            try:
                p.unlink()
            except OSError:
                pass


def main() -> int:
    return asyncio.run(_run())


if __name__ == "__main__":
    raise SystemExit(main())
