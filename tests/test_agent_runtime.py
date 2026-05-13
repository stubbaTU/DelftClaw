"""Phase-7 tests: OpenClawAgent runtime + tool-call loop end-to-end.

  - ``OpenClawAgent.start/stop`` boot a SeedboxCommunity over IPv8.
  - ``build_tools(agent).dispatch(...)`` runs the tool surface in-process.
  - ``run_tool_loop`` drives a scripted ``StubToolLoopLLM`` through:
      1. listing peers,
      2. fetching + compiling a content overlay descriptor,
      3. invoking SEARCH on it,
    and produces a final-text reply.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.peer import Peer

from agent import (
    AgentConfig,
    OpenClawAgent,
    StubToolLoopLLM,
    build_tools,
    run_tool_loop,
)
from communication.bittorrent import StubBitTorrentService
from communication.community import overlay_id
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol import StubLLMClient, community_id_from_md
from protocol.examples.content_community_stub import CONTENT_COMMUNITY_SOURCE


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTENT_MD = (REPO_ROOT / "protocol" / "examples" / "content_community.md").read_text()
CONTENT_HASH = overlay_id(CONTENT_MD)


def _stub_llm() -> StubLLMClient:
    return StubLLMClient(sources={
        community_id_from_md(CONTENT_MD).hex():
            "```python\n" + CONTENT_COMMUNITY_SOURCE + "```",
    })


@pytest_asyncio.fixture
async def two_agents(tmp_path):
    save_a = tmp_path / "a"
    save_b = tmp_path / "b"

    alice = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "army van defense carry jealous true garbage claim echo media make crunch"
        ).load(), network="TESTNET"),
        llm=_stub_llm(),
        config=AgentConfig(port=0, save_dir=save_a),
        bt_service=StubBitTorrentService(save_dir=save_a),
    )
    bob = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).load(), network="TESTNET"),
        llm=_stub_llm(),
        config=AgentConfig(port=0, save_dir=save_b),
        bt_service=StubBitTorrentService(save_dir=save_b),
    )

    await alice.start()
    await bob.start()

    addr_a = alice.address
    addr_b = bob.address
    alice.seedbox.network.add_verified_peer(Peer(bob.seedbox.my_peer.public_key, address=addr_b))
    bob.seedbox.network.add_verified_peer(Peer(alice.seedbox.my_peer.public_key, address=addr_a))

    yield alice, bob

    await alice.stop()
    await bob.stop()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_agent_starts_and_exposes_seedbox_and_registry(two_agents):
    alice, bob = two_agents
    assert alice.seedbox is not None
    assert alice.registry is not None
    assert alice.address[1] != 0  # bound to a real port


# ---------------------------------------------------------------------------
# Tools (in-process, no LLM)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tools_peers_list_returns_known_peer(two_agents):
    alice, bob = two_agents
    tools = build_tools(alice)
    result = await tools.dispatch("peers_list", {})
    assert isinstance(result, list) and len(result) == 1
    assert result[0]["mid_hex"] == bob.seedbox.my_peer.mid.hex()


@pytest.mark.asyncio
async def test_tools_overlay_publish_loads_locally(two_agents):
    alice, _bob = two_agents
    tools = build_tools(alice)
    md_hash_hex = await tools.dispatch("overlay_publish", {"md_text": CONTENT_MD})
    assert md_hash_hex == CONTENT_HASH.hex()
    listed = await tools.dispatch("overlays_list", {})
    assert any(o["community_id_hex"] == md_hash_hex for o in listed)


@pytest.mark.asyncio
async def test_tools_overlay_fetch_and_load_round_trips(two_agents):
    alice, bob = two_agents
    # Alice publishes the descriptor.
    a_tools = build_tools(alice)
    await a_tools.dispatch("overlay_publish", {"md_text": CONTENT_MD})

    # Bob asks Alice for it via the bootstrap community.
    b_tools = build_tools(bob)
    result = await b_tools.dispatch(
        "overlay_fetch_and_load",
        {"peer_mid": alice.seedbox.my_peer.mid.hex(),
         "md_hash_hex": CONTENT_HASH.hex()},
    )
    assert result["loaded"] is True
    assert result["community_id_hex"] == CONTENT_HASH.hex()


# ---------------------------------------------------------------------------
# Tool-call loop with a scripted stub LLM
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tool_loop_drives_scripted_search(two_agents):
    alice, bob = two_agents

    # Alice publishes + indexes.
    a_tools = build_tools(alice)
    await a_tools.dispatch("overlay_publish", {"md_text": CONTENT_MD})
    content_a = alice.registry.get(CONTENT_HASH)
    content_a.local_index = [
        {"magnet": "magnet:?xt=urn:btih:1", "name": "Creative Commons Audio Archive 2023.mp3",
         "size": 4200000, "mime": "audio/mpeg", "tags": ["cc"]},
    ]

    # Bob: tool loop sequence —
    #   1. peers_list
    #   2. overlay_fetch_and_load (descriptor from Alice)
    #   3. overlay_invoke SEARCH_REQUEST (query="creative")
    #   4. (assistant final text)
    alice_mid = alice.seedbox.my_peer.mid.hex()
    scripted: list[dict] = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "peers_list", "arguments": "{}"},
            }],
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "c2", "type": "function",
                "function": {
                    "name": "overlay_fetch_and_load",
                    "arguments": json.dumps({
                        "peer_mid": alice_mid,
                        "md_hash_hex": CONTENT_HASH.hex(),
                    }),
                },
            }],
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "c3", "type": "function",
                "function": {
                    "name": "overlay_invoke",
                    "arguments": json.dumps({
                        "community_id_hex": CONTENT_HASH.hex(),
                        "message_name": "SEARCH_REQUEST",
                        "peer_mid": alice_mid,
                        "fields": {"query": "creative"},
                    }),
                },
            }],
        },
        {
            "role": "assistant",
            "content": "I asked Alice and she has a Creative Commons audio file.",
        },
    ]

    # Cross-introduce Bob on the new overlay AFTER Bob loads it via fetch.
    # The loop will load it during turn 2 (overlay_fetch_and_load); we hook in
    # an after-load patch by piggybacking on the StubBitTorrentService's
    # synchronous nature: just inject the peer reference once both sides know
    # the overlay. We do that via a helper that runs after each turn — or
    # simpler, inject before invoke is reached by sleeping.
    b_tools = build_tools(bob)
    llm = StubToolLoopLLM(responses=scripted)

    loop_task = asyncio.create_task(run_tool_loop(
        "What files are on our Claw Network?", llm, b_tools, max_iterations=6,
    ))
    # Give the loop a moment to load the overlay (turn 2), then introduce
    # peers on the new overlay so the SEARCH_REQUEST in turn 3 can route.
    for _ in range(40):
        if bob.registry.get(CONTENT_HASH) is not None and \
           alice.registry.get(CONTENT_HASH) is not None:
            break
        await asyncio.sleep(0.05)
    assert bob.registry.get(CONTENT_HASH) is not None, "Bob never loaded the overlay"
    content_b = bob.registry.get(CONTENT_HASH)
    content_a = alice.registry.get(CONTENT_HASH)
    content_a.network.add_verified_peer(Peer(content_b.my_peer.public_key, address=bob.address))
    content_b.network.add_verified_peer(Peer(content_a.my_peer.public_key, address=alice.address))

    final_text = await asyncio.wait_for(loop_task, timeout=5.0)
    assert "Creative Commons" in final_text

    # And the SEARCH actually populated Bob's content community response cache.
    for _ in range(40):
        if content_b.response_cache:
            break
        await asyncio.sleep(0.05)
    assert any("Creative Commons" in r["name"] for r in content_b.response_cache)
