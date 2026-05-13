"""Tests for ``deploy.state_snapshot.collect_state``.

The watchdog hands the snapshot dict to the LLM each turn and to the
stop-predicate library — so shape stability matters. Asserts:

  * Every top-level key the design promises is present.
  * The "network" key is None pre-manifest, populated post-manifest.
  * The "peers" entries get wallet_address + known_overlays populated
    when a peer has sent its PEER_INTRO.
  * The whole snapshot is json.dumps-able (no bytes, no datetime).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import pytest_asyncio

from agent.runtime import AgentConfig, OpenClawAgent
from communication.community import PeerMeta
from deploy.state_snapshot import collect_state
from identity.agent_identity import AgentIdentity
from identity.seed import Seed
from protocol.llm import StubLLMClient


REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_MD = (REPO_ROOT / "protocol" / "examples" / "delftclaw_network.md").read_text(
    encoding="utf-8"
)


@pytest_asyncio.fixture
async def started_agent(tmp_path):
    seed = Seed(b"\x42" * 32)
    identity = AgentIdentity.from_seed(seed, network="testnet")
    agent = OpenClawAgent(
        identity=identity,
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            address="127.0.0.1",
            btc_network="testnet",
            save_dir=tmp_path / "downloads",
        ),
    )
    await agent.start()
    try:
        yield agent
    finally:
        await agent.stop()


@pytest.mark.asyncio
async def test_snapshot_has_expected_top_level_keys(started_agent):
    snap = collect_state(started_agent)
    assert set(snap.keys()) == {"ts", "agent", "network", "wallet", "peers", "overlays", "torrents"}
    assert snap["network"] is None  # no manifest loaded yet
    assert snap["peers"] == []
    assert snap["overlays"] == []


@pytest.mark.asyncio
async def test_snapshot_is_json_serializable(started_agent):
    """The watchdog renders the snapshot as JSON into the LLM prompt."""
    snap = collect_state(started_agent)
    # Should not raise.
    serialized = json.dumps(snap)
    assert isinstance(serialized, str)


@pytest.mark.asyncio
async def test_snapshot_network_populated_after_load_manifest(started_agent):
    started_agent.load_manifest(MANIFEST_MD)
    snap = collect_state(started_agent)

    net = snap["network"]
    assert net is not None
    assert net["name"] == "delftclaw_seek_cc"
    assert net["version"] == "1.0.0"
    assert len(net["network_id_hex"]) == 40   # sha1[:20] -> 40 hex chars
    assert net["admission"]["min_sats"] == 10000
    assert net["admission"]["min_confirmations"] == 0
    assert isinstance(net["genesis_peers"], list)
    assert len(net["genesis_peers"]) == 1
    assert net["default_overlays"] == [
        "0b5cafdd65c3e0021949bdc8f071d830ef5ce66f",
    ]


@pytest.mark.asyncio
async def test_snapshot_load_manifest_idempotent(started_agent):
    """Loading the same manifest twice does not double-add peers."""
    m1 = started_agent.load_manifest(MANIFEST_MD)
    peers_after_first = list(started_agent.known_peers())
    m2 = started_agent.load_manifest(MANIFEST_MD)
    assert m1.network_id == m2.network_id
    assert len(list(started_agent.known_peers())) == len(peers_after_first)


@pytest.mark.asyncio
async def test_snapshot_peer_wallet_address_surfaces_from_peer_meta(started_agent, tmp_path):
    """An entry in seedbox._peer_meta produces wallet_address + known_overlays in the snapshot."""
    from ipv8.keyvault.crypto import default_eccrypto
    from ipv8.peer import Peer

    # Inject a synthetic peer + PeerMeta directly. We're testing the snapshot
    # plumbing, not the wire-level handshake — that's covered by test_peer_intro.py.
    fake_key = default_eccrypto.generate_key("curve25519")
    fake_peer = Peer(fake_key.pub(), address=("127.0.0.1", 9999))
    started_agent.seedbox.network.add_verified_peer(fake_peer)
    started_agent.seedbox._peer_meta[fake_peer.mid] = PeerMeta(
        wallet_address="tb1qfakefakefakefakefakefakefakefakefakefa",
        known_overlays=(b"\x0b" * 20,),
    )

    snap = collect_state(started_agent)
    entries = [p for p in snap["peers"] if p["mid_hex"] == fake_peer.mid.hex()]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["wallet_address"] == "tb1qfakefakefakefakefakefakefakefakefakefa"
    assert entry["known_overlays"] == ["0b" * 20]


@pytest.mark.asyncio
async def test_snapshot_peer_without_intro_has_null_wallet(started_agent):
    """Peers we know about but who haven't introduced themselves get null wallet."""
    from ipv8.keyvault.crypto import default_eccrypto
    from ipv8.peer import Peer

    fake_peer = Peer(
        default_eccrypto.generate_key("curve25519").pub(),
        address=("127.0.0.1", 9998),
    )
    started_agent.seedbox.network.add_verified_peer(fake_peer)

    snap = collect_state(started_agent)
    entries = [p for p in snap["peers"] if p["mid_hex"] == fake_peer.mid.hex()]
    assert len(entries) == 1
    assert entries[0]["wallet_address"] is None
    assert entries[0]["known_overlays"] == []
