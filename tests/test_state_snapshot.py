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

from agent.community_state import (
    CommunityState,
    SeedboxProvisioned,
    SeedboxPurchaseIntent,
)
from agent.runtime import AgentConfig, OpenClawAgent
from communication.community import PeerMeta
from deploy.state_snapshot import _next_objective, collect_state
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
    assert set(snap.keys()) == {
        "ts",
        "agent",
        "network",
        "wallet",
        "peers",
        "overlays",
        "torrents",
        "community",
        "security",
        "next_objective",
    }
    assert snap["network"] is None  # no manifest loaded yet
    assert snap["peers"] == []
    assert snap["overlays"] == []
    # Pre-manifest, the only honest hint is "wait" — see _next_objective.
    assert snap["next_objective"] == {
        "label": "wait_for_manifest",
        "reason": "no network manifest is loaded yet; nothing to act on",
    }


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
        "a3455e9cec3b78bc281f1c495b0a08baa733833a",
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


# ---------------------------------------------------------------------------
# _next_objective: rule-table unit tests against synthetic fake agents.
# ---------------------------------------------------------------------------


class _FakeWallet:
    def __init__(self, address: str) -> None:
        self._address = address

    def address(self) -> str:
        return self._address


class _FakeTorrent:
    def __init__(self, progress: float) -> None:
        self.progress = progress


class _FakeBitTorrent:
    def __init__(self, torrents: list[_FakeTorrent]) -> None:
        self._torrents = torrents

    def stats(self) -> list[_FakeTorrent]:
        return list(self._torrents)


class _FakeAdmission:
    def __init__(
        self,
        *,
        gatekeeper_address: str,
        seedbox_cost_sats: int = 50_000,
        max_agents_per_seedbox: int = 3,
        seedbox_growth_enabled: bool = True,
    ) -> None:
        self.gatekeeper_address = gatekeeper_address
        self.seedbox_cost_sats = seedbox_cost_sats
        self.max_agents_per_seedbox = max_agents_per_seedbox
        self.seedbox_growth_enabled = seedbox_growth_enabled


class _FakeManifest:
    def __init__(self, admission: _FakeAdmission) -> None:
        self.admission = admission


class _FakeAgent:
    def __init__(
        self,
        *,
        manifest: _FakeManifest | None,
        state: CommunityState | None,
        reporter_id: str = "me-reporter",
        wallet_address: str = "tb1qme",
        torrents: list[_FakeTorrent] | None = None,
    ) -> None:
        self.network_manifest = manifest
        self._state = state
        self.community_reporter_id = reporter_id
        self.wallet = _FakeWallet(wallet_address)
        self.bittorrent = _FakeBitTorrent(torrents or [])

    def community_state(self) -> CommunityState | None:
        return self._state


def _state(
    *,
    members: set[str],
    balance_sats: int,
    purchases: tuple[SeedboxPurchaseIntent, ...] = (),
    provisioned: tuple[SeedboxProvisioned, ...] = (),
    seedbox_count: int = 1,
) -> CommunityState:
    return CommunityState(
        members=frozenset(members),
        donations=(),
        purchases=purchases,
        provisioned=provisioned,
        balance_sats=balance_sats,
        seedbox_count=seedbox_count,
    )


def test_next_objective_wait_when_no_manifest():
    agent = _FakeAgent(manifest=None, state=None)
    assert _next_objective(agent) == {
        "label": "wait_for_manifest",
        "reason": "no network manifest is loaded yet; nothing to act on",
    }


def test_next_objective_wait_when_no_community_state():
    manifest = _FakeManifest(_FakeAdmission(gatekeeper_address="tb1qfounder"))
    agent = _FakeAgent(manifest=manifest, state=None)
    obj = _next_objective(agent)
    assert obj is not None
    assert obj["label"] == "wait_for_manifest"


def test_next_objective_bootstrap_treasury_for_empty_treasury_founder():
    manifest = _FakeManifest(_FakeAdmission(gatekeeper_address="tb1qfounder"))
    state = _state(members=set(), balance_sats=0)
    agent = _FakeAgent(
        manifest=manifest, state=state, wallet_address="tb1qfounder"
    )
    obj = _next_objective(agent)
    assert obj is not None
    assert obj["label"].startswith("bootstrap_treasury")
    assert "community_donate_and_join" in obj["label"]


def test_next_objective_wait_for_founder_when_treasury_empty_and_not_founder():
    manifest = _FakeManifest(_FakeAdmission(gatekeeper_address="tb1qfounder"))
    state = _state(members=set(), balance_sats=0)
    agent = _FakeAgent(
        manifest=manifest, state=state, wallet_address="tb1qjoiner"
    )
    obj = _next_objective(agent)
    assert obj is not None
    assert obj["label"] == "wait_for_founder"


def test_next_objective_join_community_when_outsider_with_funded_treasury():
    manifest = _FakeManifest(_FakeAdmission(gatekeeper_address="tb1qfounder"))
    state = _state(members={"founder-reporter"}, balance_sats=100_000)
    agent = _FakeAgent(
        manifest=manifest,
        state=state,
        reporter_id="joiner-reporter",
        wallet_address="tb1qjoiner",
    )
    obj = _next_objective(agent)
    assert obj is not None
    assert obj["label"].startswith("join_community")
    assert "community_donate_and_join" in obj["label"]


def test_next_objective_retrieve_content_when_admitted_joiner_has_no_torrent():
    manifest = _FakeManifest(_FakeAdmission(gatekeeper_address="tb1qfounder"))
    state = _state(members={"me-reporter"}, balance_sats=100_000)
    agent = _FakeAgent(
        manifest=manifest,
        state=state,
        wallet_address="tb1qjoiner",  # not the gatekeeper
        torrents=[],
    )
    obj = _next_objective(agent)
    assert obj is not None
    assert obj["label"].startswith("retrieve_content")
    assert "content_search_and_fetch" in obj["label"]


def test_next_objective_skips_retrieve_for_founder():
    """Founder seeds content — never needs to 'retrieve'."""
    manifest = _FakeManifest(_FakeAdmission(gatekeeper_address="tb1qfounder"))
    state = _state(members={"me-reporter"}, balance_sats=100_000)
    agent = _FakeAgent(
        manifest=manifest,
        state=state,
        wallet_address="tb1qfounder",
        torrents=[],
    )
    # Founder admitted, no retrieval needed, no threshold tripped → None.
    assert _next_objective(agent) is None


def test_next_objective_propose_seedbox_when_threshold_active_and_treasury_sufficient():
    manifest = _FakeManifest(
        _FakeAdmission(
            gatekeeper_address="tb1qfounder",
            seedbox_cost_sats=50_000,
            max_agents_per_seedbox=3,
        )
    )
    # 4 members, capacity 3 × 1 seedbox = 3 → threshold tripped.
    state = _state(
        members={"a", "b", "c", "d"},
        balance_sats=60_000,
        seedbox_count=1,
    )
    agent = _FakeAgent(
        manifest=manifest,
        state=state,
        reporter_id="a",
        wallet_address="tb1qjoiner",
        # Has a completed torrent already so we skip 'retrieve_content'.
        torrents=[_FakeTorrent(progress=1.0)],
    )
    obj = _next_objective(agent)
    assert obj is not None
    assert obj["label"].startswith("propose_seedbox_purchase")
    assert "seedbox_purchase_propose" in obj["label"]


def test_next_objective_record_provisioned_when_own_intent_open():
    manifest = _FakeManifest(_FakeAdmission(gatekeeper_address="tb1qfounder"))
    open_intent = SeedboxPurchaseIntent(
        reporter_id="me-reporter",
        cost_sats=50_000,
        timestamp="2026-05-25T12:00:00Z",
        entry_hash="hash-open",
    )
    closed_intent = SeedboxPurchaseIntent(
        reporter_id="me-reporter",
        cost_sats=50_000,
        timestamp="2026-05-24T12:00:00Z",
        entry_hash="hash-closed",
    )
    state = _state(
        members={"me-reporter"},
        balance_sats=10_000,
        purchases=(open_intent, closed_intent),
        provisioned=(
            SeedboxProvisioned(
                reporter_id="me-reporter",
                purchase_intent_hash="hash-closed",
                seedbox_url="mock://seed",
                seedbox_pubkey_hex="00" * 32,
                timestamp="2026-05-24T12:30:00Z",
                entry_hash="prov-hash",
            ),
        ),
        seedbox_count=2,
    )
    agent = _FakeAgent(
        manifest=manifest,
        state=state,
        wallet_address="tb1qjoiner",
        torrents=[_FakeTorrent(progress=1.0)],
    )
    obj = _next_objective(agent)
    assert obj is not None
    assert obj["label"].startswith("record_seedbox_provisioned")
    assert "seedbox_provisioned" in obj["label"]


def test_next_objective_none_when_everything_satisfied():
    manifest = _FakeManifest(
        _FakeAdmission(
            gatekeeper_address="tb1qfounder",
            max_agents_per_seedbox=3,
        )
    )
    # 3 members, capacity 3 → threshold NOT active.
    state = _state(
        members={"a", "b", "me-reporter"}, balance_sats=100_000, seedbox_count=1
    )
    agent = _FakeAgent(
        manifest=manifest,
        state=state,
        wallet_address="tb1qjoiner",
        torrents=[_FakeTorrent(progress=1.0)],
    )
    assert _next_objective(agent) is None


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
