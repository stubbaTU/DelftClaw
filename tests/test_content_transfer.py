"""Phase-8 tests: CONTENT_REQUEST / CONTENT_DELIVERY byte transfer over IPv8.

Mirrors the OVERLAY-exchange tests in ``tests/test_overlay_registry.py`` but
moves *file bytes* between two real IPv8 nodes rather than markdown. The
property under test is the self-verifying transport: the receiver MUST refuse
any payload whose sha1 does not equal the requested ``content_id``.
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.community import SeedboxCommunity, content_id_for_bytes


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
    from ipv8.keyvault.crypto import default_eccrypto

    key_a = tmp_path / "a.key"
    key_b = tmp_path / "b.key"
    key_a.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())
    key_b.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())

    svc_a = _build_node(0, key_a)
    svc_b = _build_node(0, key_b)
    await svc_a.start()
    await svc_b.start()

    sb_a = next(o for o in svc_a.overlays if isinstance(o, SeedboxCommunity))
    sb_b = next(o for o in svc_b.overlays if isinstance(o, SeedboxCommunity))

    addr_a = sb_a.endpoint.get_address()
    addr_b = sb_b.endpoint.get_address()
    peer_a_for_b = Peer(sb_a.my_peer.public_key, address=addr_a)
    peer_b_for_a = Peer(sb_b.my_peer.public_key, address=addr_b)
    sb_a.network.add_verified_peer(peer_b_for_a)
    sb_b.network.add_verified_peer(peer_a_for_b)

    yield svc_a, svc_b, sb_a, sb_b, peer_a_for_b, peer_b_for_a

    await svc_a.stop()
    await svc_b.stop()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_publish_and_fetch_returns_real_bytes(tmp_path, two_nodes):
    svc_a, svc_b, sb_a, sb_b, peer_a_for_b, peer_b_for_a = two_nodes
    payload = b"# Calculus excerpt\nthe limit of a function\n" * 4
    file_a = tmp_path / "calculus.txt"
    file_a.write_bytes(payload)

    cid = content_id_for_bytes(payload)
    sb_a.publish_content(cid, file_a)

    fut = sb_b.fetch_content(peer_a_for_b, cid)
    received = await asyncio.wait_for(fut, timeout=2.0)
    assert received == payload
    assert hashlib.sha1(received).digest() == cid


@pytest.mark.asyncio
async def test_fetch_unknown_content_times_out(two_nodes):
    """A fetcher asking for a content_id the seeder never published must
    not resolve. Confirms there is no fabricated success path (the false-
    green from the old stub transport)."""
    svc_a, svc_b, sb_a, sb_b, peer_a_for_b, peer_b_for_a = two_nodes
    fut = sb_b.fetch_content(peer_a_for_b, b"\x00" * 20)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(fut, timeout=0.4)


# ---------------------------------------------------------------------------
# Self-verification: a malicious seeder swapping bytes must be rejected.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_delivery_with_mismatched_hash_is_rejected(tmp_path, two_nodes):
    """If the seeder swaps the underlying file between publish and request,
    ``on_content_request`` refuses to ship the now-wrong bytes — the fetcher's
    pending future never resolves. Even if a custom peer bypassed that and
    sent mismatched bytes directly, ``on_content_delivery`` would drop them
    before set_result. End-to-end: no resolution, hash never lies."""
    svc_a, svc_b, sb_a, sb_b, peer_a_for_b, peer_b_for_a = two_nodes
    original = b"original content for sha1 binding\n" * 3
    file_a = tmp_path / "swap.txt"
    file_a.write_bytes(original)

    cid = content_id_for_bytes(original)
    sb_a.publish_content(cid, file_a)
    # Swap the bytes on disk AFTER publish; the request-time hash check now
    # disagrees with the requested content_id, so the seeder refuses to ship.
    file_a.write_bytes(b"swapped: I am DIFFERENT now\n" * 3)

    fut = sb_b.fetch_content(peer_a_for_b, cid)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(fut, timeout=0.4)


def test_published_content_accessor_round_trips(tmp_path):
    """publish_content registers a content_id → path entry the publisher can
    introspect for testing / debugging."""
    from ipv8.keyvault.crypto import default_eccrypto

    # We don't need IPv8 wiring for this — instantiate the bookkeeping side.
    payload = b"hello"
    file_a = tmp_path / "x.txt"
    file_a.write_bytes(payload)
    cid = content_id_for_bytes(payload)

    # Smoke-test publish_content as a pure data operation via the accessor.
    # (Building an IPv8 instance just to call publish_content would be heavier
    # than the property under test warrants; the round-trip is covered by
    # test_publish_and_fetch_returns_real_bytes above.)
    class _Dummy:
        _content_store: dict[bytes, Path] = {}
        publish_content = SeedboxCommunity.publish_content
        published_content = SeedboxCommunity.published_content

    d = _Dummy()
    d.publish_content(cid, file_a)
    assert d.published_content == {cid: file_a}
