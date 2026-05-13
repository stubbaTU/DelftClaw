"""Phase-5 tests: the content_community descriptor compiles + searches.

  - The descriptor parses under the schema and produces a stable community_id.
  - All five test vectors round-trip on encode + decode.
  - End-to-end: peer A indexes a directory, peer B compiles the descriptor
    and issues a SEARCH_REQUEST, results land in B's response_cache.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8.keyvault.crypto import default_eccrypto
from ipv8_service import IPv8

from communication.community import SeedboxCommunity, overlay_id
from protocol import OverlayRegistry, StubLLMClient, community_id_from_md, compile_overlay
from protocol.examples.content_community_stub import CONTENT_COMMUNITY_SOURCE


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTENT_MD = (REPO_ROOT / "protocol" / "examples" / "content_community.md").read_text()
CONTENT_HASH = overlay_id(CONTENT_MD)


def _stub_llm() -> StubLLMClient:
    return StubLLMClient(sources={
        community_id_from_md(CONTENT_MD).hex():
            "```python\n" + CONTENT_COMMUNITY_SOURCE + "```",
    })


def _build_node(port: int, key_path: Path) -> IPv8:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.set_address("127.0.0.1")
    builder.add_key("anchor", "curve25519", str(key_path))
    builder.add_overlay("SeedboxCommunity", "anchor", [], [], {}, [("started",)])
    return IPv8(builder.finalize(), extra_communities={"SeedboxCommunity": SeedboxCommunity})


@pytest_asyncio.fixture
async def two_nodes(tmp_path):
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
    sb_a.network.add_verified_peer(Peer(sb_b.my_peer.public_key, address=addr_b))
    sb_b.network.add_verified_peer(Peer(sb_a.my_peer.public_key, address=addr_a))
    yield svc_a, svc_b, sb_a, sb_b, addr_a, addr_b
    await svc_a.stop()
    await svc_b.stop()


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------

def test_content_community_compiles_and_passes_test_vectors():
    compiled = compile_overlay(CONTENT_MD, _stub_llm())
    assert compiled.community_id == CONTENT_HASH
    assert set(compiled.payload_classes) == {"SEARCH_REQUEST", "SEARCH_RESPONSE"}


# ---------------------------------------------------------------------------
# End-to-end: A indexes a directory, B searches, results land in B's cache.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_search_round_trip(two_nodes):
    svc_a, svc_b, sb_a, sb_b, addr_a, addr_b = two_nodes

    reg_a = OverlayRegistry(svc_a, _stub_llm())
    reg_b = OverlayRegistry(svc_b, _stub_llm())
    content_a = reg_a.load(CONTENT_MD)
    content_b = reg_b.load(CONTENT_MD)

    # Cross-introduce on the new overlay.
    content_a.network.add_verified_peer(Peer(content_b.my_peer.public_key, address=addr_b))
    content_b.network.add_verified_peer(Peer(content_a.my_peer.public_key, address=addr_a))

    # Alice (A) indexes a tiny library.
    content_a.local_index = [
        {"magnet": "magnet:?xt=urn:btih:111", "name": "Creative Commons Audio Archive 2023.mp3",
         "size": 4200000, "mime": "audio/mpeg", "tags": ["cc", "audio"]},
        {"magnet": "magnet:?xt=urn:btih:222", "name": "lecture-physics.mp4",
         "size": 99000000, "mime": "video/mp4", "tags": ["edu"]},
        {"magnet": "magnet:?xt=urn:btih:333", "name": "creative_commons_book.pdf",
         "size": 5400000, "mime": "application/pdf", "tags": ["cc", "book"]},
    ]

    # Bob (B) sends SEARCH_REQUEST(query="creative") -- substring matches name
    # in the Audio Archive entry and the "creative_commons_book.pdf" entry,
    # but not "lecture-physics.mp4".
    SearchRequestPayload = reg_b._compiled[CONTENT_HASH].payload_classes["SEARCH_REQUEST"]
    content_b.ez_send(
        Peer(content_a.my_peer.public_key, address=addr_a),
        SearchRequestPayload(b"creative"),
    )

    for _ in range(40):
        if len(content_b.response_cache) >= 2:
            break
        await asyncio.sleep(0.05)

    names = [r["name"] for r in content_b.response_cache]
    assert "Creative Commons Audio Archive 2023.mp3" in names
    assert "creative_commons_book.pdf" in names
    assert "lecture-physics.mp4" not in names

    # And a tag-only match: query "edu" hits via the tags joined into the haystack.
    content_b.response_cache.clear()
    content_b.ez_send(
        Peer(content_a.my_peer.public_key, address=addr_a),
        SearchRequestPayload(b"edu"),
    )
    for _ in range(40):
        if content_b.response_cache:
            break
        await asyncio.sleep(0.05)
    assert [r["name"] for r in content_b.response_cache] == ["lecture-physics.mp4"]


@pytest.mark.asyncio
async def test_empty_query_returns_full_index(two_nodes):
    svc_a, svc_b, sb_a, sb_b, addr_a, addr_b = two_nodes
    reg_a = OverlayRegistry(svc_a, _stub_llm())
    reg_b = OverlayRegistry(svc_b, _stub_llm())
    content_a = reg_a.load(CONTENT_MD)
    content_b = reg_b.load(CONTENT_MD)

    content_a.network.add_verified_peer(Peer(content_b.my_peer.public_key, address=addr_b))
    content_b.network.add_verified_peer(Peer(content_a.my_peer.public_key, address=addr_a))

    content_a.local_index = [
        {"magnet": "magnet:?xt=urn:btih:1", "name": "a", "size": 1, "mime": "x"},
        {"magnet": "magnet:?xt=urn:btih:2", "name": "b", "size": 2, "mime": "x"},
    ]

    SearchRequestPayload = reg_b._compiled[CONTENT_HASH].payload_classes["SEARCH_REQUEST"]
    content_b.ez_send(
        Peer(content_a.my_peer.public_key, address=addr_a),
        SearchRequestPayload(b""),
    )
    for _ in range(40):
        if len(content_b.response_cache) >= 2:
            break
        await asyncio.sleep(0.05)
    assert len(content_b.response_cache) == 2
