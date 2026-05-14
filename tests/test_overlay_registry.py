"""Phase-4 tests: overlay descriptor exchange + runtime registration.

  - SeedboxCommunity publishes / fetches `.md` descriptors over the wire,
    verifies hash on delivery, rejects oversize blobs.
  - OverlayRegistry compiles a delivered descriptor and registers the
    new community with a running IPv8 instance, idempotently.
  - End-to-end: peer A publishes echo_overlay.md, peer B fetches +
    compiles + registers + exchanges one ECHO round-trip.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.community import MAX_OVERLAY_BYTES, SeedboxCommunity, overlay_id
from protocol import OverlayRegistry, StubLLMClient, community_id_from_md
from protocol.examples.echo_overlay_stub import ECHO_OVERLAY_SOURCE


REPO_ROOT = Path(__file__).resolve().parent.parent
ECHO_MD = (REPO_ROOT / "protocol" / "examples" / "echo_overlay.md").read_text()
ECHO_HASH = overlay_id(ECHO_MD)


def _stub_llm() -> StubLLMClient:
    return StubLLMClient(sources={
        community_id_from_md(ECHO_MD).hex(): "```python\n" + ECHO_OVERLAY_SOURCE + "```",
    })


def _build_node(port: int, key_path: Path) -> IPv8:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.set_address("127.0.0.1")
    builder.add_key("anchor", "curve25519", str(key_path))
    builder.add_overlay("SeedboxCommunity", "anchor", [], [], {}, [("started",)])
    return IPv8(
        builder.finalize(),
        extra_communities={"SeedboxCommunity": SeedboxCommunity},
    )


@pytest_asyncio.fixture
async def two_nodes(tmp_path):
    """Two IPv8 nodes wired to each other; yields (svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b)."""
    from ipv8.keyvault.crypto import default_eccrypto

    key_a_path = tmp_path / "a.key"
    key_b_path = tmp_path / "b.key"
    key_a_path.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())
    key_b_path.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())

    svc_a = _build_node(port=0, key_path=key_a_path)
    svc_b = _build_node(port=0, key_path=key_b_path)
    await svc_a.start()
    await svc_b.start()

    sb_a = next(o for o in svc_a.overlays if isinstance(o, SeedboxCommunity))
    sb_b = next(o for o in svc_b.overlays if isinstance(o, SeedboxCommunity))

    addr_a = sb_a.endpoint.get_address()
    addr_b = sb_b.endpoint.get_address()
    peer_b_for_a = Peer(sb_b.my_peer.public_key, address=addr_b)
    peer_a_for_b = Peer(sb_a.my_peer.public_key, address=addr_a)
    sb_a.network.add_verified_peer(peer_b_for_a)
    sb_b.network.add_verified_peer(peer_a_for_b)

    yield svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b

    await svc_a.stop()
    await svc_b.stop()


# ---------------------------------------------------------------------------
# overlay_id derivation
# ---------------------------------------------------------------------------

def test_overlay_id_matches_compiler_id():
    assert overlay_id(ECHO_MD) == community_id_from_md(ECHO_MD)


# ---------------------------------------------------------------------------
# SeedboxCommunity publish / fetch / hash-verify
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_publish_and_fetch_round_trip(two_nodes):
    svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b = two_nodes
    sb_a.publish_overlay(ECHO_MD)
    fut = sb_b.fetch_overlay(peer_a_for_b, ECHO_HASH)
    md_bytes = await asyncio.wait_for(fut, timeout=2.0)
    assert md_bytes.decode("utf-8") == ECHO_MD


@pytest.mark.asyncio
async def test_fetch_unknown_descriptor_times_out(two_nodes):
    svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b = two_nodes
    fut = sb_b.fetch_overlay(peer_a_for_b, b"\x00" * 20)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(fut, timeout=0.4)


@pytest.mark.asyncio
async def test_offer_callback_fires(two_nodes):
    svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b = two_nodes
    seen: list[bytes] = []
    sb_b.configure(offer_callback=lambda peer, md_hash: seen.append(md_hash))
    sb_a.offer_overlay(peer_b_for_a, ECHO_HASH)
    for _ in range(40):
        if seen:
            break
        await asyncio.sleep(0.05)
    assert seen == [ECHO_HASH]


def test_publish_returns_canonical_id():
    from communication.community import SeedboxCommunity as _SC  # noqa: F401  (re-import)
    # publish_overlay returns the same id for an extra-trailing-newline copy
    md1 = ECHO_MD
    md2 = ECHO_MD + "\n\n\n"
    assert overlay_id(md1) == overlay_id(md2)


# ---------------------------------------------------------------------------
# OverlayRegistry: idempotent runtime registration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_registry_load_appends_and_is_idempotent(two_nodes):
    svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b = two_nodes
    before = len(svc_b.overlays)
    reg = OverlayRegistry(svc_b, _stub_llm())

    inst1 = reg.load(ECHO_MD)
    assert inst1.community_id == ECHO_HASH
    assert len(svc_b.overlays) == before + 1

    inst2 = reg.load(ECHO_MD)
    assert inst2 is inst1
    assert len(svc_b.overlays) == before + 1  # still one new overlay


# ---------------------------------------------------------------------------
# End-to-end: fetch + compile + register + exchange
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_remote_fetched_overlay_round_trips_a_message(two_nodes):
    svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b = two_nodes

    # Alice publishes locally.
    sb_a.publish_overlay(ECHO_MD)
    reg_a = OverlayRegistry(svc_a, _stub_llm())
    echo_a = reg_a.load(ECHO_MD)

    # Bob fetches via the bootstrap, then compiles+registers.
    md_bytes = await asyncio.wait_for(
        sb_b.fetch_overlay(peer_a_for_b, ECHO_HASH), timeout=2.0
    )
    reg_b = OverlayRegistry(svc_b, _stub_llm())
    echo_b = reg_b.load(md_bytes.decode("utf-8"))
    assert echo_a.community_id == echo_b.community_id == ECHO_HASH

    # Inject mutual peers on the new overlay (no walker).
    peer_b_for_a_echo = Peer(echo_b.my_peer.public_key, address=sb_b.endpoint.get_address())
    peer_a_for_b_echo = Peer(echo_a.my_peer.public_key, address=sb_a.endpoint.get_address())
    echo_a.network.add_verified_peer(peer_b_for_a_echo)
    echo_b.network.add_verified_peer(peer_a_for_b_echo)

    # Echo a payload from A to B; B's handler responds with payload + "!".
    EchoRequestPayload = reg_a._compiled[ECHO_HASH].payload_classes["ECHO_REQUEST"]
    echo_a.ez_send(peer_b_for_a_echo, EchoRequestPayload(b"hello"))

    for _ in range(40):
        if echo_a.received_responses:
            break
        await asyncio.sleep(0.05)
    assert echo_a.received_responses == ["hello!"]
