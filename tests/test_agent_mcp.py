"""Smoke tests for the FastMCP server that exposes the agent's tools to OpenClaw.

The FastMCP ``Client`` accepts a ``FastMCP`` instance directly as its transport
(an "in-memory transport"), so we can round-trip MCP calls without binding a
socket — the same code path OpenClaw exercises over streamable-HTTP, minus
the wire.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import pytest_asyncio
from fastmcp import Client
from ipv8.peer import Peer

from agent import AgentConfig, OpenClawAgent
from agent.mcp_server import build_mcp_server
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
async def two_agents_with_mcp(tmp_path):
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
# Tools surface
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mcp_server_lists_the_full_tool_surface(two_agents_with_mcp):
    """The full v5.1+ community tool surface must appear on FastMCP.

    Regression guard: previous v5.1 iterations added new tools to
    ``agent/tools.py`` (the offline tool-call path) without mirroring
    them in ``agent/mcp_server.py`` (the production path the watchdog
    actually uses). That left scenario_boot calling tools that the
    real MCP server didn't expose.
    """
    alice, _bob = two_agents_with_mcp
    server = build_mcp_server(alice)
    async with Client(server) as client:
        tools = await client.list_tools()
    names = {t.name for t in tools}
    assert names == {
        "peers_list", "peer_add",
        "wallet_address", "wallet_balance", "wallet_send",
        "seedbox_donate_and_join",
        "community_log_list_recent", "community_treasury_balance",
        "community_member_count", "community_donate_and_join",
        "community_join_via_peer", "seedbox_purchase_propose",
        "seedbox_provisioned",
        "overlays_list", "overlay_describe", "overlay_fetch_and_load",
        "overlay_publish", "overlay_invoke",
        "agent_inject_manifest", "network_join",
        "torrent_seed", "torrent_fetch", "torrent_stats",
    }


@pytest.mark.asyncio
async def test_mcp_peer_add_round_trips_a_new_peer(tmp_path):
    """peer_add over MCP introduces a peer to every overlay's network."""
    from agent import AgentConfig, OpenClawAgent
    from communication.bittorrent import StubBitTorrentService
    from identity.agent_identity import AgentIdentity
    from identity.seed import MnemonicSeedSource

    # Isolated lone agent: no fixture peer pre-introduced. The post-condition
    # we want is "peer_add adds someone the agent didn't know about."
    solo = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        ).load(), network="TESTNET"),
        llm=_stub_llm(),
        config=AgentConfig(port=0, save_dir=tmp_path),
        bt_service=StubBitTorrentService(save_dir=tmp_path),
    )
    await solo.start()

    # Another identity we'll introduce.
    other = AgentIdentity.from_seed(MnemonicSeedSource(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).load(), network="TESTNET")

    try:
        server = build_mcp_server(solo)
        async with Client(server) as client:
            result = await client.call_tool(
                "peer_add",
                {
                    "host": "127.0.0.1",
                    "port": 8199,
                    "pubkey_hex": other.ipv8.pubkey.hex(),
                },
            )
        payload = json.loads(result.content[0].text)
        assert payload["mid_hex"]  # 40 hex chars; just confirm it's present
        assert payload["address"] == [
            "127.0.0.1", 8199,
        ] or payload["address"] == ["127.0.0.1", 8199]
        # Verify the peer landed in the seedbox network.
        peers = solo.known_peers()
        assert any(p.mid.hex() == payload["mid_hex"] for p in peers)
    finally:
        await solo.stop()


@pytest.mark.asyncio
async def test_mcp_peers_list_returns_known_peer(two_agents_with_mcp):
    alice, bob = two_agents_with_mcp
    server = build_mcp_server(alice)
    async with Client(server) as client:
        result = await client.call_tool("peers_list", {})
    payload = json.loads(result.content[0].text) if result.content else result.structured_content
    if isinstance(payload, dict) and "result" in payload:
        payload = payload["result"]
    assert isinstance(payload, list) and len(payload) == 1
    assert payload[0]["mid_hex"] == bob.seedbox.my_peer.mid.hex()


@pytest.mark.asyncio
async def test_mcp_wallet_address_is_deterministic(two_agents_with_mcp):
    alice, _bob = two_agents_with_mcp
    server = build_mcp_server(alice)
    async with Client(server) as client:
        result = await client.call_tool("wallet_address", {})
    text = result.content[0].text
    assert text == alice.wallet.address()


# ---------------------------------------------------------------------------
# End-to-end: an OpenClaw-equivalent client drives the full SEARCH flow
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mcp_client_can_publish_fetch_and_invoke_overlay(two_agents_with_mcp):
    alice, bob = two_agents_with_mcp
    # Alice publishes locally via the MCP surface.
    server_a = build_mcp_server(alice)
    server_b = build_mcp_server(bob)

    async with Client(server_a) as client_a:
        published_hex = (await client_a.call_tool("overlay_publish", {"md_text": CONTENT_MD})).content[0].text
    assert published_hex == CONTENT_HASH.hex()

    content_a = alice.registry.get(CONTENT_HASH)
    content_a.local_index = [
        {"magnet": "magnet:?xt=urn:btih:1",
         "name": "Creative Commons Audio Archive 2023.mp3",
         "size": 4200000, "mime": "audio/mpeg"},
    ]

    # Bob (via his MCP server) fetches+loads the overlay from Alice.
    async with Client(server_b) as client_b:
        load_result = await client_b.call_tool(
            "overlay_fetch_and_load",
            {"peer_mid": alice.seedbox.my_peer.mid.hex(),
             "md_hash_hex": CONTENT_HASH.hex()},
        )
        load_payload = json.loads(load_result.content[0].text)
        assert load_payload["loaded"] is True

        # Cross-introduce on the new overlay (in production this happens
        # because the OFFER carried the peer's mid + the gatekeeper relays
        # addresses; for the test we wire it manually).
        content_b = bob.registry.get(CONTENT_HASH)
        content_b.network.add_verified_peer(Peer(content_a.my_peer.public_key, address=alice.address))
        content_a.network.add_verified_peer(Peer(content_b.my_peer.public_key, address=bob.address))

        await client_b.call_tool(
            "overlay_invoke",
            {"community_id_hex": CONTENT_HASH.hex(),
             "message_name": "SEARCH_REQUEST",
             "peer_mid": alice.seedbox.my_peer.mid.hex(),
             "fields": {"query": "creative"}},
        )

    # Wait briefly for the wire round-trip.
    for _ in range(40):
        if content_b.response_cache:
            break
        await asyncio.sleep(0.05)
    assert any("Creative Commons" in r["name"] for r in content_b.response_cache)


# ---------------------------------------------------------------------------
# v5.1 manifest tools (the surface scenario_boot drives over MCP)
# ---------------------------------------------------------------------------

def _build_manifest_md_for_test(alice: OpenClawAgent) -> str:
    return (
        "# Identity\n"
        "- name: test_network\n"
        "- version: 1.0.0\n"
        "- description: MCP smoke test manifest.\n"
        "\n"
        "# Admission\n"
        f"- gatekeeper_address: {alice.wallet.address()}\n"
        "- min_sats: 10000\n"
        "- min_confirmations: 0\n"
        "\n"
        "# Genesis Peers\n"
        "| host | port | pubkey_hex |\n"
        "|------|------|------------|\n"
        f"| 127.0.0.1 | {alice.address[1]} | {alice.pubkey_hex} |\n"
        "\n"
        "# Default Overlays\n"
        f"- sha1: {CONTENT_HASH.hex()}  (content_community v1)\n"
    )


@pytest.mark.asyncio
async def test_mcp_agent_inject_manifest_round_trips(two_agents_with_mcp):
    """The exact MCP call ``deploy.scenario_boot`` issues at Phase 4b."""
    alice, _bob = two_agents_with_mcp
    md_text = _build_manifest_md_for_test(alice)

    server_a = build_mcp_server(alice)
    async with Client(server_a) as client:
        result = await client.call_tool("agent_inject_manifest", {"md_text": md_text})
    payload = json.loads(result.content[0].text)
    assert "error" not in payload
    assert payload["name"] == "test_network"
    assert payload["genesis_peers"] == 1
    assert payload["default_overlays"] == [CONTENT_HASH.hex()]

    # Alice's runtime now has the manifest cached and (since she's named
    # as the genesis) has published it via the bootstrap community.
    assert alice.network_manifest is not None
    from communication.community import manifest_id
    assert manifest_id(md_text) in alice.seedbox.published_manifests


@pytest.mark.asyncio
async def test_mcp_overlays_list_exposes_full_message_schema(two_agents_with_mcp):
    """v5.1 overlays_list must surface field encodings, not just message names."""
    alice, _bob = two_agents_with_mcp
    server_a = build_mcp_server(alice)
    async with Client(server_a) as client:
        await client.call_tool("overlay_publish", {"md_text": CONTENT_MD})
        result = await client.call_tool("overlays_list", {})
    payload = json.loads(result.content[0].text)
    # FastMCP wraps single-list results either as a list or under {"result":}.
    if isinstance(payload, dict) and "result" in payload:
        payload = payload["result"]
    entry = next(o for o in payload if o["community_id_hex"] == CONTENT_HASH.hex())

    msg = next(m for m in entry["messages"] if m["name"] == "SEARCH_REQUEST")
    assert msg["msg_id"] == 1
    assert msg["fields"] == [
        {"name": "query", "encoding": "varlenH-utf8",
         "description": "utf-8 search string; empty string returns the full index"},
    ]
    assert "scan ``self.local_index``" in msg["handler_text"].lower()


@pytest.mark.asyncio
async def test_mcp_overlay_describe_returns_canonical_md(two_agents_with_mcp):
    alice, _bob = two_agents_with_mcp
    server_a = build_mcp_server(alice)
    async with Client(server_a) as client:
        await client.call_tool("overlay_publish", {"md_text": CONTENT_MD})
        result = await client.call_tool(
            "overlay_describe",
            {"community_id_hex": CONTENT_HASH.hex()},
        )
    payload = json.loads(result.content[0].text)
    assert payload["truncated"] is False
    assert "# Identity" in payload["md_text"]
    assert "SEARCH_REQUEST" in payload["md_text"]


@pytest.mark.asyncio
async def test_mcp_network_join_uses_cached_manifest_when_no_arg(two_agents_with_mcp):
    """After inject, network_join() with no args must use the cached manifest."""
    alice, bob = two_agents_with_mcp
    md_text = _build_manifest_md_for_test(alice)

    # Wire Alice as gatekeeper (accept-everything verifier) and Bob's wallet
    # as a mock so .send() doesn't try to broadcast on testnet.
    from admission.donation_verifier import DonationVerification

    class _Accept:
        def verify(self, _txid_hex: str) -> DonationVerification:
            return DonationVerification(accepted=True, paid_sats=10_000, confirmations=1)

    alice.seedbox.configure(verifier=_Accept())
    alice.seedbox.publish_overlay(CONTENT_MD)
    sends: list[tuple[str, int]] = []

    def _fake_send(to: str, sats: int) -> str:
        sends.append((to, sats))
        return "aa" * 32

    bob.wallet.send = _fake_send  # type: ignore[method-assign]

    server_b = build_mcp_server(bob)
    async with Client(server_b) as client:
        await client.call_tool("agent_inject_manifest", {"md_text": md_text})
        result = await client.call_tool("network_join", {})
    payload = json.loads(result.content[0].text)

    assert "error" not in payload, payload
    assert payload["accepted"] is True
    assert payload["overlays_loaded"] == [CONTENT_HASH.hex()]
    assert sends == [(alice.wallet.address(), 10000)]
