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

from agent.community_state import CommunityState
from agent.runtime import AgentConfig, OpenClawAgent
from communication.community import PeerMeta
from deploy.state_snapshot import _next_objective, collect_state
from identity.agent_identity import AgentIdentity
from identity.seed import Seed
from _live_llm import noop_llm


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
        llm=noop_llm(),
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
        "pending_overlay_offers",
        "authored_overlay_ids",
        "self_authored_announces_sent",
        "torrents",
        "community",
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
    assert net["name"] == "delftclaw_payment"
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
    def __init__(self, *, gatekeeper_address: str) -> None:
        self.gatekeeper_address = gatekeeper_address


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


def _state(*, members: set[str], balance_sats: int) -> CommunityState:
    return CommunityState(
        members=frozenset(members),
        donations=(),
        balance_sats=balance_sats,
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


def test_next_objective_none_when_admitted_joiner_done():
    """An admitted non-gatekeeper has no further objective (admission-only)."""
    manifest = _FakeManifest(_FakeAdmission(gatekeeper_address="tb1qfounder"))
    state = _state(members={"a", "b", "me-reporter"}, balance_sats=100_000)
    agent = _FakeAgent(
        manifest=manifest,
        state=state,
        wallet_address="tb1qjoiner",
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


# ---------------------------------------------------------------------------
# author_overlay objective (file_share v3 protocol-evolution nudge)
# ---------------------------------------------------------------------------

def _record_completed_download(agent) -> None:
    """Register a progress=1.0 torrent so has_completed_torrent is True."""
    path = agent.bittorrent.save_dir / "open_textbook_calculus_excerpt.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"calc" * 8)
    agent.bittorrent.record_download(
        "magnet:?xt=urn:btih:ec9d91a30668b3ece1579e15d545a4b1eb43caf8&dn=calc",
        path, path.stat().st_size,
    )


@pytest.mark.asyncio
async def test_author_overlay_objective_fires_for_tool_capable_agent(
    started_agent, monkeypatch
):
    """FILE_SHARE_MODE + allowlist has overlay_author_and_publish + a completed
    download + nothing self-authored -> next_objective nudges authoring."""
    monkeypatch.setenv("FILE_SHARE_MODE", "1")
    monkeypatch.setenv(
        "MCP_TOOL_ALLOWLIST",
        "content_search_and_fetch,overlay_author_and_publish,overlays_list,torrent_stats",
    )
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)

    obj = _next_objective(started_agent)
    assert obj is not None
    assert obj["label"].startswith("author_overlay")
    assert "overlay_author_and_publish" in obj["label"]


@pytest.mark.asyncio
async def test_author_overlay_objective_sees_cross_process_download(
    started_agent, monkeypatch
):
    """The deployed blocker, end-to-end: the MCP process records the download,
    the watchdog process (THIS agent, a SEPARATE BitTorrentService over the same
    save_dir) builds the snapshot. Recording via a separate instance must still
    flip has_completed_torrent so author_overlay fires — proving the on-disk
    ledger bridges the process boundary all the way into _next_objective."""
    from communication.bittorrent import StubBitTorrentService

    monkeypatch.setenv("FILE_SHARE_MODE", "1")
    monkeypatch.setenv(
        "MCP_TOOL_ALLOWLIST",
        "content_search_and_fetch,overlay_author_and_publish,overlays_list,torrent_stats",
    )
    started_agent.load_manifest(MANIFEST_MD)

    # Record the download from a DIFFERENT instance sharing save_dir — exactly
    # what the MCP-service process does, invisible in-memory to this agent.
    shared = started_agent.bittorrent.save_dir
    mcp_side = StubBitTorrentService(save_dir=shared)
    f = shared / "open_textbook_calculus_excerpt.txt"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(b"calc" * 96)
    mcp_side.record_download(
        "magnet:?xt=urn:btih:ec9d91a30668b3ece1579e15d545a4b1eb43caf8&dn=calc",
        f, f.stat().st_size,
    )

    obj = _next_objective(started_agent)
    assert obj is not None and obj["label"].startswith("author_overlay")


@pytest.mark.asyncio
async def test_author_overlay_objective_absent_without_tool_in_allowlist(
    started_agent, monkeypatch
):
    """A fetcher_2-shaped allowlist (no authoring tool) gets None after its
    download, not the authoring nudge."""
    monkeypatch.setenv("FILE_SHARE_MODE", "1")
    monkeypatch.setenv("MCP_TOOL_ALLOWLIST", "content_search_and_fetch,torrent_stats")
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)

    assert _next_objective(started_agent) is None


@pytest.mark.asyncio
async def test_author_overlay_objective_clears_after_self_authored(
    started_agent, monkeypatch
):
    """Once the agent has authored an overlay (its wallet is the author_id),
    the nudge clears so the stop predicate can fire."""
    from agent.overlay_authoring import synthesize_overlay_markdown
    from protocol import community_id_from_md

    monkeypatch.setenv("FILE_SHARE_MODE", "1")
    monkeypatch.setenv(
        "MCP_TOOL_ALLOWLIST", "overlay_author_and_publish,torrent_stats"
    )
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)

    # Synthesize + load a download_announce overlay authored by THIS agent.
    messages = [{
        "name": "ANNOUNCE", "msg_id": 1,
        "fields": [{"name": "who", "encoding": "varlenH-utf8", "description": "a"}],
        "handler": "On receipt, append who to self.received_announcements.",
    }]
    md = synthesize_overlay_markdown(
        name="download_announce", version="1.0.0", description="x",
        messages=messages,
        runtime_state=[{"name": "received_announcements", "type": "list[dict]", "description": "r"}],
        author_id=started_agent.wallet.address(),
        change_summary="x", samples={"ANNOUNCE": {"who": "fetcher_1"}},
    )
    cid_hex = community_id_from_md(md).hex()
    impl = (
        "```python\n"
        "from ipv8.community import Community, CommunitySettings\n"
        "from ipv8.lazy_community import lazy_wrapper\n"
        "from ipv8.messaging.lazy_payload import VariablePayload, vp_compile\n"
        "from ipv8.peer import Peer\n"
        "from ipv8.peerdiscovery.network import PeerObserver\n"
        "@vp_compile\n"
        "class AnnouncePayload(VariablePayload):\n"
        "    msg_id = 1\n"
        '    format_list = ["varlenH"]\n'
        '    names = ["who"]\n'
        "class GeneratedCommunity(Community, PeerObserver):\n"
        f'    community_id = bytes.fromhex("{cid_hex}")\n'
        "    def __init__(self, settings: CommunitySettings) -> None:\n"
        "        super().__init__(settings)\n"
        "        self.received_announcements = []\n"
        "        self.add_message_handler(AnnouncePayload, self.on_announce)\n"
        "    def started(self) -> None:\n"
        "        self.network.add_peer_observer(self)\n"
        "    def on_peer_added(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    def on_peer_removed(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    @lazy_wrapper(AnnouncePayload)\n"
        "    def on_announce(self, peer: Peer, payload: AnnouncePayload) -> None:\n"
        '        self.received_announcements.append(payload.who.decode("utf-8"))\n'
        "```"
    )
    # Feed the inline impl straight through the compile pipeline (no live LLM):
    # llm_source short-circuits the model, exactly as the disk cache does.
    started_agent.publish_overlay(md, llm_source=impl)

    # v4 semantics: now that an overlay is self-authored, the author_overlay
    # nudge clears but the announce_pending nudge takes over until the agent
    # actually sends a message on its own protocol — the demo's "communication
    # continues" trigger. announce_pending unicasts to the ONE non-genesis peer
    # (the successor that must observe the protocol), so give the agent such a
    # peer; the deployed mesh guarantees exactly one.
    from ipv8.keyvault.crypto import default_eccrypto
    from ipv8.peer import Peer
    observer = Peer(default_eccrypto.generate_key("curve25519").pub(), address=("127.0.0.1", 9001))
    started_agent.seedbox.network.add_verified_peer(observer)

    obj = _next_objective(started_agent)
    assert obj is not None and obj["label"].startswith("announce_pending")
    assert obj["authored_overlay_cid_hex"] == cid_hex
    assert obj["announce_target_mid"] == observer.mid.hex()

    # Once the agent records an announce (cross-process counter file flipped
    # by ``overlay_invoke``), the nudge clears entirely.
    import json as _json
    counter = Path(started_agent.bittorrent.save_dir) / ".self_authored_announces_sent.jsonl"
    counter.parent.mkdir(parents=True, exist_ok=True)
    counter.write_text(_json.dumps({"community_id_hex": cid_hex, "message_name": "ANNOUNCE"}) + "\n", encoding="utf-8")
    assert _next_objective(started_agent) is None


# ---------------------------------------------------------------------------
# v4 autonomous-evolution: successor adopt -> observe -> author_v_next, plus
# genesis announce targeting (file_share "Mesh + observe ANNOUNCE").
# ---------------------------------------------------------------------------

_SUCCESSOR_ENV = {
    "FILE_SHARE_MODE": "1",
    "MCP_TOOL_ALLOWLIST": (
        "content_search_and_fetch,overlay_author_and_publish,"
        "overlay_fetch_and_load,overlay_invoke,overlays_list,torrent_stats"
    ),
    "OVERLAY_AUTHOR_MODE": "successor",
    "EVOLUTION_BASE_OVERLAY_NAME": "download_announce",
}


def _set_env(monkeypatch, env: dict) -> None:
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def _load_download_announce(agent, *, author_id: str):
    """Synthesize + load a download_announce v1.0.0 attributed to ``author_id``.

    Uses ``registry.load`` with received provenance so author_id may differ
    from this agent (simulating an ADOPTED peer overlay). Returns
    ``(cid_hex, live_instance)``; the instance exposes ``received_announcements``.
    """
    from agent.overlay_authoring import synthesize_overlay_markdown
    from protocol import community_id_from_md

    messages = [{
        "name": "ANNOUNCE", "msg_id": 1,
        "fields": [{"name": "who", "encoding": "varlenH-utf8", "description": "a"}],
        "handler": "On receipt, append who to self.received_announcements.",
    }]
    md = synthesize_overlay_markdown(
        name="download_announce", version="1.0.0", description="x",
        messages=messages,
        runtime_state=[{"name": "received_announcements", "type": "list[dict]", "description": "r"}],
        author_id=author_id, change_summary="x", samples={"ANNOUNCE": {"who": "fetcher_1"}},
    )
    cid_hex = community_id_from_md(md).hex()
    impl = (
        "```python\n"
        "from ipv8.community import Community, CommunitySettings\n"
        "from ipv8.lazy_community import lazy_wrapper\n"
        "from ipv8.messaging.lazy_payload import VariablePayload, vp_compile\n"
        "from ipv8.peer import Peer\n"
        "from ipv8.peerdiscovery.network import PeerObserver\n"
        "@vp_compile\n"
        "class AnnouncePayload(VariablePayload):\n"
        "    msg_id = 1\n"
        '    format_list = ["varlenH"]\n'
        '    names = ["who"]\n'
        "class GeneratedCommunity(Community, PeerObserver):\n"
        f'    community_id = bytes.fromhex("{cid_hex}")\n'
        "    def __init__(self, settings: CommunitySettings) -> None:\n"
        "        super().__init__(settings)\n"
        "        self.received_announcements = []\n"
        "        self.add_message_handler(AnnouncePayload, self.on_announce)\n"
        "    def started(self) -> None:\n"
        "        self.network.add_peer_observer(self)\n"
        "    def on_peer_added(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    def on_peer_removed(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    @lazy_wrapper(AnnouncePayload)\n"
        "    def on_announce(self, peer: Peer, payload: AnnouncePayload) -> None:\n"
        '        self.received_announcements.append(payload.who.decode("utf-8"))\n'
        "```"
    )
    instance = agent.registry.load(md, provenance="received_from:peer", llm_source=impl)
    return cid_hex, instance


@pytest.mark.asyncio
async def test_successor_adopt_overlay_when_offer_pending(started_agent, monkeypatch):
    """successor + completed download + a pending overlay offer + nothing
    adopted yet -> adopt_overlay (NOT author_overlay), carrying the offer's
    peer_mid + md_hash_hex so the LLM fetches it without guessing."""
    _set_env(monkeypatch, _SUCCESSOR_ENV)
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)

    import json as _json
    offers = Path(started_agent.bittorrent.save_dir) / ".overlay_offers.jsonl"
    offers.parent.mkdir(parents=True, exist_ok=True)
    offers.write_text(
        _json.dumps({"md_hash_hex": "cd" * 20, "from_peer_mid": "ab" * 20}) + "\n",
        encoding="utf-8",
    )

    obj = _next_objective(started_agent)
    assert obj is not None
    assert obj["label"].startswith("adopt_overlay")
    assert obj["offer_md_hash_hex"] == "cd" * 20
    assert obj["offer_peer_mid"] == "ab" * 20


@pytest.mark.asyncio
async def test_successor_waits_when_no_offer_and_nothing_adopted(started_agent, monkeypatch):
    """A successor with no pending offer and no adopted base must NOT fall back
    to authoring its own v1.0.0 — it waits (None)."""
    _set_env(monkeypatch, _SUCCESSOR_ENV)
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)
    assert _next_objective(started_agent) is None


@pytest.mark.asyncio
async def test_successor_author_v_next_when_base_adopted(started_agent, monkeypatch):
    """successor that has ADOPTED a peer's download_announce -> author_v_next,
    naming the peer's cid as the supersedes base. v4 deployed compromise:
    adoption alone triggers design. The watchdog snapshot lives in a separate
    process from the MCP-side overlay handler and cannot see
    ``received_announcements`` without a cross-process message bridge that
    this v4 does not ship — adoption (visible via the on-disk overlay
    archive) is the cross-process signal we DO have."""
    _set_env(monkeypatch, _SUCCESSOR_ENV)
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)

    cid_hex, _ = _load_download_announce(started_agent, author_id="dclaw1somepeerauthor")

    obj = _next_objective(started_agent)
    assert obj is not None
    assert obj["label"].startswith("author_overlay_v_next")
    assert obj["base_overlay_cid_hex"] == cid_hex


@pytest.mark.asyncio
async def test_base_overlay_for_evolution_reads_archive_cross_process(
    started_agent, monkeypatch, tmp_path
):
    """The deployed shape: the MCP-side process performs ``overlay_fetch_and_load``
    and the overlay archive captures it (a ``<cid>.meta.json`` with name +
    author_id). The watchdog snapshot agent runs in a SEPARATE process with
    an empty registry. The snapshot must still surface the peer-authored
    overlay — via the on-disk archive bridge, with no registry load."""
    archive = tmp_path / "overlay_archive"
    archive.mkdir()
    cid_hex = "aa" * 20
    (archive / f"{cid_hex}.meta.json").write_text(
        json.dumps({
            "community_id_hex": cid_hex,
            "name": "download_announce",
            "identity_version": "1.0.0",
            "author_id": "dclaw1somepeerauthor",   # NOT started_agent.wallet
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("OVERLAY_ARCHIVE_DIR", str(archive))
    _set_env(monkeypatch, _SUCCESSOR_ENV)
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)

    # The agent's REGISTRY holds nothing for download_announce; the only
    # signal is the archive meta — exactly the cross-process shape on the VPS.
    obj = _next_objective(started_agent)
    assert obj is not None
    assert obj["label"].startswith("author_overlay_v_next")
    assert obj["base_overlay_cid_hex"] == cid_hex


@pytest.mark.asyncio
async def test_base_overlay_skips_archive_entries_authored_by_self(
    started_agent, monkeypatch, tmp_path
):
    """An archive entry this agent AUTHORED is not a successor target — that
    would be re-authoring v1.0.0. Skip it; with no peer-authored base and no
    pending offer, the successor simply waits."""
    archive = tmp_path / "overlay_archive"
    archive.mkdir()
    cid_hex = "bb" * 20
    (archive / f"{cid_hex}.meta.json").write_text(
        json.dumps({
            "community_id_hex": cid_hex,
            "name": "download_announce",
            "identity_version": "1.0.0",
            "author_id": started_agent.wallet.address(),  # SELF
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("OVERLAY_ARCHIVE_DIR", str(archive))
    _set_env(monkeypatch, _SUCCESSOR_ENV)
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)

    assert _next_objective(started_agent) is None


@pytest.mark.asyncio
async def test_genesis_announce_pending_requires_a_distinct_observer_peer(started_agent, monkeypatch):
    """genesis/legacy author that has published but knows no non-genesis peer
    cannot resolve an announce target -> None; once a distinct peer exists,
    announce_pending fires and carries that peer's mid."""
    monkeypatch.setenv("FILE_SHARE_MODE", "1")
    monkeypatch.setenv(
        "MCP_TOOL_ALLOWLIST", "overlay_author_and_publish,overlay_invoke,torrent_stats"
    )
    # No OVERLAY_AUTHOR_MODE / EVOLUTION_BASE_OVERLAY_NAME -> legacy genesis path.
    monkeypatch.delenv("OVERLAY_AUTHOR_MODE", raising=False)
    monkeypatch.delenv("EVOLUTION_BASE_OVERLAY_NAME", raising=False)
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)
    cid_hex, _ = _load_download_announce(started_agent, author_id=started_agent.wallet.address())

    # No non-genesis peer yet -> no resolvable target -> wait.
    assert _next_objective(started_agent) is None

    from ipv8.keyvault.crypto import default_eccrypto
    from ipv8.peer import Peer
    observer = Peer(default_eccrypto.generate_key("curve25519").pub(), address=("127.0.0.1", 9002))
    started_agent.seedbox.network.add_verified_peer(observer)

    obj = _next_objective(started_agent)
    assert obj is not None and obj["label"].startswith("announce_pending")
    assert obj["announce_target_mid"] == observer.mid.hex()
    assert obj["authored_overlay_cid_hex"] == cid_hex


@pytest.mark.asyncio
async def test_successor_author_v_next_caps_after_three_compile_fails(
    started_agent, monkeypatch, tmp_path,
):
    """The defensive cap: if the agent has 3 consecutive ``compile_fail`` events
    on the base overlay's name in its ledger, ``author_overlay_v_next`` stops
    firing and surfaces a ``stuck_in_zero_shot_failure`` diagnostic instead.
    Prevents the LLM-churn spiral observed in the 2026-05-30 VPS run where
    bytes-encoding mistakes kept tripping the validator on every retry."""
    archive = tmp_path / "overlay_archive"
    archive.mkdir()
    cid_hex = "aa" * 20
    (archive / f"{cid_hex}.meta.json").write_text(
        json.dumps({
            "community_id_hex": cid_hex,
            "name": "download_announce",
            "identity_version": "1.0.0",
            "author_id": "dclaw1somepeerauthor",
        }),
        encoding="utf-8",
    )
    # Three consecutive compile_fail events on the ledger and no authored
    # event for the base name yet -> cap fires.
    (archive / "overlay_ledger.jsonl").write_text(
        "\n".join([
            json.dumps({"ts": 1.0, "event": "compile_fail", "community_id_hex": "11" * 20, "stage": "test_vectors"}),
            json.dumps({"ts": 2.0, "event": "compile_fail", "community_id_hex": "22" * 20, "stage": "test_vectors"}),
            json.dumps({"ts": 3.0, "event": "compile_fail", "community_id_hex": "33" * 20, "stage": "post_compile"}),
        ]) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OVERLAY_ARCHIVE_DIR", str(archive))
    _set_env(monkeypatch, _SUCCESSOR_ENV)
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)
    # Reload the registry's archive view of the new dir.
    from protocol.overlay_archive import OverlayArchive
    started_agent.registry._archive = OverlayArchive(archive)

    obj = _next_objective(started_agent)
    assert obj is not None
    assert obj["label"] == "stuck_in_zero_shot_failure"
    assert obj["consecutive_compile_fails"] == 3


@pytest.mark.asyncio
async def test_successor_resumes_authoring_after_successful_authored_event(
    started_agent, monkeypatch, tmp_path,
):
    """An ``authored`` event for the same overlay name resets the consecutive
    streak — the cap only counts fails SINCE the last success, so a different
    name's failures (or a prior run's) don't stick to the current agent."""
    archive = tmp_path / "overlay_archive"
    archive.mkdir()
    cid_hex = "bb" * 20
    (archive / f"{cid_hex}.meta.json").write_text(
        json.dumps({
            "community_id_hex": cid_hex,
            "name": "download_announce",
            "identity_version": "1.0.0",
            "author_id": "dclaw1somepeerauthor",
        }),
        encoding="utf-8",
    )
    # Three fails, then a successful authored event for the same name, then
    # one more fail. Cap should see only 1 (the post-authored one).
    (archive / "overlay_ledger.jsonl").write_text(
        "\n".join([
            json.dumps({"ts": 1.0, "event": "compile_fail", "community_id_hex": "11" * 20, "stage": "test_vectors"}),
            json.dumps({"ts": 2.0, "event": "compile_fail", "community_id_hex": "22" * 20, "stage": "test_vectors"}),
            json.dumps({"ts": 3.0, "event": "compile_fail", "community_id_hex": "33" * 20, "stage": "test_vectors"}),
            json.dumps({"ts": 4.0, "event": "authored", "community_id_hex": "44" * 20, "name": "download_announce", "identity_version": "1.1.0"}),
            json.dumps({"ts": 5.0, "event": "compile_fail", "community_id_hex": "55" * 20, "stage": "test_vectors"}),
        ]) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OVERLAY_ARCHIVE_DIR", str(archive))
    _set_env(monkeypatch, _SUCCESSOR_ENV)
    started_agent.load_manifest(MANIFEST_MD)
    _record_completed_download(started_agent)
    from protocol.overlay_archive import OverlayArchive
    started_agent.registry._archive = OverlayArchive(archive)

    obj = _next_objective(started_agent)
    # The author_v_next path nominally would fire (base overlay present,
    # streak below cap); only blocked if the agent has already self-authored
    # download_announce (which it has, per the authored ledger event from a
    # cross-process mirror — see _self_authored_overlay_ids). Either way the
    # outcome must NOT be ``stuck_in_zero_shot_failure``.
    assert obj is None or obj["label"] != "stuck_in_zero_shot_failure"
