"""In-process tool test for ``content_fetch_via_transfer``.

Two real OpenClawAgents wired as IPv8 peers, both running the content_community
(discovery) and file_transfer (chunked transport) overlays. The seeder's
catalogue + served store hold one multi-chunk file; the fetcher dispatches the
new tool and must end with the verified bytes on disk and a recorded download.
This is the in-process analogue of the deploy/scenarios/file_transfer demo.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.peer import Peer

from agent import AgentConfig, OpenClawAgent
from agent.content_fetch import content_fetch_via_transfer_impl
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol.compiler import community_id_from_md
from communication.bittorrent import StubBitTorrentService
from _live_llm import live_compiler_llm, requires_live_llm

CONTENT_MD = Path("protocol/examples/content_community.md").read_text(encoding="utf-8")
FT_MD = Path("protocol/examples/file_transfer_overlay.md").read_text(encoding="utf-8")
CONTENT_CID = community_id_from_md(CONTENT_MD)
FT_CID = community_id_from_md(FT_MD)

# Drives a full discovery + chunked-transfer fetch, compiling BOTH overlays via
# a real LLM on both agents, so the module skips without an endpoint.
pytestmark = requires_live_llm


@pytest_asyncio.fixture
async def two_agents(tmp_path):
    save_a, save_b = tmp_path / "a", tmp_path / "b"
    seeder = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "army van defense carry jealous true garbage claim echo media make crunch"
        ).load(), network="TESTNET"),
        llm=live_compiler_llm(),
        config=AgentConfig(port=0, save_dir=save_a),
        bt_service=StubBitTorrentService(save_dir=save_a),
    )
    fetcher = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).load(), network="TESTNET"),
        llm=live_compiler_llm(),
        config=AgentConfig(port=0, save_dir=save_b),
        bt_service=StubBitTorrentService(save_dir=save_b),
    )
    await seeder.start()
    await fetcher.start()
    seeder.seedbox.network.add_verified_peer(Peer(fetcher.seedbox.my_peer.public_key, address=fetcher.address))
    fetcher.seedbox.network.add_verified_peer(Peer(seeder.seedbox.my_peer.public_key, address=seeder.address))
    yield seeder, fetcher
    await seeder.stop()
    await fetcher.stop()


def _introduce_on(agent_a, agent_b, cid) -> None:
    """Cross-introduce the two agents as peers of the overlay ``cid``."""
    ov_a = agent_a.registry.get(cid)
    ov_b = agent_b.registry.get(cid)
    ov_a.network.add_verified_peer(Peer(agent_b.seedbox.my_peer.public_key, address=agent_b.address))
    ov_b.network.add_verified_peer(Peer(agent_a.seedbox.my_peer.public_key, address=agent_a.address))
    ov_a.network.discover_services(Peer(agent_b.seedbox.my_peer.public_key, address=agent_b.address), [cid])
    ov_b.network.discover_services(Peer(agent_a.seedbox.my_peer.public_key, address=agent_a.address), [cid])


@pytest.mark.asyncio
async def test_content_fetch_via_transfer_downloads_and_verifies(two_agents):
    seeder, fetcher = two_agents

    # Both agents load both overlays.
    for agent in (seeder, fetcher):
        await agent.registry.aload(CONTENT_MD, provenance="test")
        await agent.registry.aload(FT_MD, provenance="test")
    _introduce_on(seeder, fetcher, CONTENT_CID)
    _introduce_on(seeder, fetcher, FT_CID)

    # Seed the seeder: catalogue (content_community) + served store (file_transfer).
    content = bytes(range(256)) * 2 + b"final"   # 517 bytes -> 3 chunks at CHUNK_SIZE=256
    content_id = hashlib.sha1(content).digest()[:20]
    magnet = f"magnet:?xt=urn:btih:{content_id.hex()}&dn=bigfile.bin"
    seeder.registry.get(CONTENT_CID).local_index = [
        {"magnet": magnet, "name": "bigfile.bin", "size": len(content),
         "mime": "application/octet-stream", "tags": ["test"]},
    ]
    seeder.registry.get(FT_CID).served = {content_id: content}

    result = await content_fetch_via_transfer_impl(fetcher, query="bigfile", pick="first", timeout_s=10.0)

    assert "error" not in result, result
    assert result["transport"] == "file_transfer_overlay"
    assert result["chunks"] == 3
    assert result["verified_size_bytes"] == len(content)
    out = Path(result["download_path"])
    assert out.is_file() and out.read_bytes() == content
    # record_download fired -> the torrent_progress_gte_1 predicate would see it.
    assert any(float(t.progress) >= 1.0 for t in fetcher.bittorrent.stats())


@pytest.mark.asyncio
async def test_content_fetch_via_transfer_errors_when_overlay_absent(two_agents):
    """Only content_community loaded (no file_transfer) -> clean error, no crash."""
    seeder, fetcher = two_agents
    for agent in (seeder, fetcher):
        await agent.registry.aload(CONTENT_MD, provenance="test")
    _introduce_on(seeder, fetcher, CONTENT_CID)
    seeder.registry.get(CONTENT_CID).local_index = [
        {"magnet": "magnet:?xt=urn:btih:" + "aa" * 20 + "&dn=x", "name": "x",
         "size": 1, "mime": "text/plain", "tags": []},
    ]
    result = await content_fetch_via_transfer_impl(fetcher, query="x", pick="first", timeout_s=3.0)
    assert result.get("error") == "file_transfer_overlay_not_loaded"
