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
from protocol import community_id_from_md
from _live_llm import live_compiler_llm, requires_live_llm


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTENT_MD = (REPO_ROOT / "protocol" / "examples" / "content_community.md").read_text()
CONTENT_HASH = overlay_id(CONTENT_MD)

# The MCP tool surface tests publish/compile content_community via a real LLM,
# so the module skips without a configured endpoint (stubs were removed).
pytestmark = requires_live_llm


@pytest_asyncio.fixture
async def two_agents_with_mcp(tmp_path):
    save_a = tmp_path / "a"
    save_b = tmp_path / "b"

    alice = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "army van defense carry jealous true garbage claim echo media make crunch"
        ).load(), network="TESTNET"),
        llm=live_compiler_llm(),
        config=AgentConfig(port=0, save_dir=save_a),
        bt_service=StubBitTorrentService(save_dir=save_a),
    )
    bob = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).load(), network="TESTNET"),
        llm=live_compiler_llm(),
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
        "community_log_list_recent", "community_treasury_balance",
        "community_member_count", "community_donate_and_join",
        "community_join_via_peer",
        "request_payment", "send_payment",
        "overlays_list", "overlay_describe", "overlay_fetch_and_load",
        "overlay_publish", "overlay_invoke", "overlay_author_and_publish",
        "agent_inject_manifest",
        "torrent_seed", "torrent_fetch", "torrent_stats",
        "content_search_and_fetch", "content_fetch_via_transfer",
    }


@pytest.mark.asyncio
async def test_mcp_tool_allowlist_filters_tools_list(
    two_agents_with_mcp, monkeypatch
):
    """When MCP_TOOL_ALLOWLIST is set, only listed tools (plus BOOTSTRAP_TOOLS)
    are advertised.

    The env var is read at ``build_mcp_server`` time, so the test sets
    it via ``monkeypatch`` before constructing the server and asserts
    the resulting ``tools/list`` round-trip returns exactly the allowed
    subset + the bootstrap exemption set.
    """
    from agent.mcp_server import BOOTSTRAP_TOOLS

    alice, _bob = two_agents_with_mcp
    monkeypatch.setenv(
        "MCP_TOOL_ALLOWLIST", "content_search_and_fetch,torrent_stats"
    )
    server = build_mcp_server(alice)
    async with Client(server) as client:
        tools = await client.list_tools()
    names = {t.name for t in tools}
    assert names == {"content_search_and_fetch", "torrent_stats"} | set(
        BOOTSTRAP_TOOLS
    )


@pytest.mark.asyncio
async def test_mcp_tool_allowlist_empty_value_keeps_only_bootstrap_tools(
    two_agents_with_mcp, monkeypatch
):
    """MCP_TOOL_ALLOWLIST set to empty string suppresses everything except
    the always-on BOOTSTRAP_TOOLS that scenario_boot calls at boot.
    """
    from agent.mcp_server import BOOTSTRAP_TOOLS

    alice, _bob = two_agents_with_mcp
    monkeypatch.setenv("MCP_TOOL_ALLOWLIST", "")
    server = build_mcp_server(alice)
    async with Client(server) as client:
        tools = await client.list_tools()
    assert {t.name for t in tools} == set(BOOTSTRAP_TOOLS)


@pytest.mark.asyncio
async def test_mcp_tool_allowlist_absent_exposes_full_surface(
    two_agents_with_mcp, monkeypatch
):
    """No MCP_TOOL_ALLOWLIST env var falls back to the legacy full surface."""
    alice, _bob = two_agents_with_mcp
    monkeypatch.delenv("MCP_TOOL_ALLOWLIST", raising=False)
    server = build_mcp_server(alice)
    async with Client(server) as client:
        tools = await client.list_tools()
    names = {t.name for t in tools}
    # Sanity: at least the search tool and the wallet trio are present.
    assert "content_search_and_fetch" in names
    assert "wallet_address" in names
    assert "torrent_fetch" in names


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
        llm=live_compiler_llm(),
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


# ---------------------------------------------------------------------------
# Tool-call audit + IPv8 content transfer via the MCP wrapper
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mcp_dispatch_emits_TOOL_call_audit_line(two_agents_with_mcp, caplog):
    """Every MCP-dispatched tool call must emit a ``TOOL call name=…`` line on
    the ``delftclaw.agent.tools`` logger so deploy/trace.py's _tool_histogram
    (and ``make tools`` / ``make tools-summary``) surface it. Before this
    wrapper, the deployed file_share + community_demo scenarios looked tool-
    silent in the journal even though they were dispatching every turn."""
    import logging

    alice, _bob = two_agents_with_mcp
    server = build_mcp_server(alice)
    with caplog.at_level(logging.INFO, logger="delftclaw.agent.tools"):
        async with Client(server) as client:
            await client.call_tool("peers_list", {})

    msgs = [r.getMessage() for r in caplog.records if r.name == "delftclaw.agent.tools"]
    assert any(m.startswith("TOOL call name=peers_list") for m in msgs)
    assert any(m.startswith("TOOL ok   name=peers_list") for m in msgs)


@pytest.mark.asyncio
async def test_mcp_content_search_and_fetch_uses_ipv8_content_transport(
    two_agents_with_mcp, tmp_path
):
    """The MCP-served ``content_search_and_fetch`` must use the IPv8
    CONTENT_REQUEST/CONTENT_DELIVERY transport (via the shared
    ``agent.content_fetch`` helper) — NOT the legacy ``torrent_fetch`` stub
    path. End-to-end: Alice publishes a real file via ``publish_content``;
    Bob's MCP tool fetches it; the bytes on Bob's disk equal Alice's source,
    sha1 verifies, and ``torrent_stats`` reports a real progress=1.0."""
    import hashlib

    from communication.community import content_id_for_bytes

    alice, bob = two_agents_with_mcp
    # Both load the content overlay.
    alice.publish_overlay(CONTENT_MD)
    bob.publish_overlay(CONTENT_MD)
    content_a = alice.registry.get(CONTENT_HASH)
    content_b = bob.registry.get(CONTENT_HASH)
    content_a.network.add_verified_peer(Peer(content_b.my_peer.public_key, address=bob.address))
    content_b.network.add_verified_peer(Peer(content_a.my_peer.public_key, address=alice.address))

    # Alice indexes a single real file + publishes its content.
    payload = b"# CC0 pancakes recipe\nflour, milk, eggs\n" * 4
    src = alice.bittorrent.save_dir / "pancakes.txt"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_bytes(payload)
    cid = content_id_for_bytes(payload)
    alice.seedbox.publish_content(cid, src)
    content_a.local_index = [{
        "magnet": f"magnet:?xt=urn:btih:{cid.hex()}&dn=pancakes.txt",
        "name": "pancakes.txt",
        "size": len(payload),
        "mime": "text/plain",
        "tags": ["recipe"],
    }]

    # Bob's MCP-side tool call → shared helper → IPv8 CONTENT path → real bytes.
    server = build_mcp_server(bob)
    async with Client(server) as client:
        result = await client.call_tool(
            "content_search_and_fetch",
            {"query": "pancakes", "pick": "first", "timeout_s": 3.0},
        )
    payload_json = json.loads(result.content[0].text)
    assert "error" not in payload_json, payload_json
    assert payload_json["verified_size_bytes"] == len(payload)
    assert payload_json["content_id_hex"] == cid.hex()

    landed = Path(payload_json["download_path"])
    assert landed.is_file()
    assert landed.read_bytes() == payload
    assert hashlib.sha1(landed.read_bytes()).digest() == cid

    # And the stop predicate's signal is real now: torrent_stats reports the
    # actual file (not a fabricated stub-<btih>.bin placeholder).
    progress_ok = any(
        t.name == landed.name and float(t.progress) >= 1.0
        for t in bob.bittorrent.stats()
    )
    assert progress_ok


@pytest.mark.asyncio
async def test_mcp_overlay_author_and_publish_authors_and_offers(
    two_agents_with_mcp, monkeypatch, tmp_path
):
    """Authoring via the MCP tool: Alice synthesizes + publishes a new overlay,
    it loads locally with her wallet as author_id, and the offer reaches Bob's
    pending_overlay_offers. This is the agent-authored-protocol path end to end
    through the deployed tool surface (the synthesized spec compiles via the
    stub LLM both agents share)."""
    from agent.overlay_authoring import synthesize_overlay_markdown
    from protocol import community_id_from_md

    alice, bob = two_agents_with_mcp
    monkeypatch.setenv("OVERLAY_ARCHIVE_DIR", str(tmp_path / "alice_arch"))

    # Pre-load the stub LLM with the implementation for the EXACT spec the tool
    # will synthesize, so the live compile resolves offline. We compute the cid
    # by synthesizing the same markdown the tool will.
    messages = [{
        "name": "ANNOUNCE", "msg_id": 1,
        "fields": [
            {"name": "who", "encoding": "varlenH-utf8", "description": "a"},
            {"name": "filename", "encoding": "varlenH-utf8", "description": "f"},
            {"name": "size_bytes", "encoding": "uint32-be", "description": "s"},
        ],
        "handler": "On receipt, append {who, filename, size_bytes} to self.received_announcements.",
    }]
    state = [{"name": "received_announcements", "type": "list[dict]", "description": "r"}]
    expected_md = synthesize_overlay_markdown(
        name="download_announce", version="1.0.0",
        description="Announce a completed download to peers.",
        messages=messages, runtime_state=state,
        author_id=alice.wallet.address(),
        change_summary="Announce a completed download to peers.",
        samples={"ANNOUNCE": {"who": "fetcher_1", "filename": "calc.txt", "size_bytes": 382}},
    )
    cid_hex = community_id_from_md(expected_md).hex()

    # The authoring tool compiles the synthesized descriptor via the live LLM.
    server = build_mcp_server(alice)
    async with Client(server) as client:
        result = await client.call_tool("overlay_author_and_publish", {
            "name": "download_announce", "version": "1.0.0",
            "description": "Announce a completed download to peers.",
            "change_summary": "Announce a completed download to peers.",
            "messages": messages, "runtime_state": state,
            "samples": {"ANNOUNCE": {"who": "fetcher_1", "filename": "calc.txt", "size_bytes": 382}},
        })
    payload = json.loads(result.content[0].text)
    assert "error" not in payload, payload
    assert payload["community_id_hex"] == cid_hex
    assert payload["author_id"] == alice.wallet.address()
    assert payload["offered_to_peers"] >= 1

    # Alice runs it locally.
    assert alice.registry.get(bytes.fromhex(cid_hex)) is not None

    # Bob received the OVERLAY_OFFER -> shows up in his pending offers.
    for _ in range(40):
        offers = bob.pending_overlay_offers()
        if any(o["md_hash_hex"] == cid_hex for o in offers):
            break
        await asyncio.sleep(0.05)
    assert any(o["md_hash_hex"] == cid_hex for o in bob.pending_overlay_offers())


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

    # Alice's runtime now has the manifest parsed + cached.
    assert alice.network_manifest is not None


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


