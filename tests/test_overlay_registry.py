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
import json
import logging
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.community import MAX_OVERLAY_BYTES, SeedboxCommunity, overlay_id
from protocol import OverlayRegistry, canonicalize_md, community_id_from_md
from _live_llm import noop_llm


REPO_ROOT = Path(__file__).resolve().parent.parent
ECHO_MD = (REPO_ROOT / "protocol" / "examples" / "echo_overlay.md").read_text()
ECHO_HASH = overlay_id(ECHO_MD)


# Inline echo implementation template. These registry tests exercise caching,
# archiving, provenance, and compile-serialization — mechanics that need *a*
# working compile but do not test the LLM or compiler correctness. Rather than
# hit a live model on every load, a tiny in-file double (``_EchoLLM``, in the
# idiom of this file's existing ``SlowLLM``) returns this source for whatever
# community_id the descriptor declares. ``{CID}`` is substituted per compile.
_ECHO_SOURCE_TMPL = '''\
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver


@vp_compile
class EchoRequestPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenH"]
    names = ["payload"]


@vp_compile
class EchoResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["varlenH"]
    names = ["payload"]


class GeneratedCommunity(Community, PeerObserver):
    community_id = bytes.fromhex("{CID}")

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(EchoRequestPayload, self.on_echo_request)
        self.add_message_handler(EchoResponsePayload, self.on_echo_response)
        self.received_responses = []

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, peer: Peer) -> None:
        pass

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    @lazy_wrapper(EchoRequestPayload)
    def on_echo_request(self, peer: Peer, payload: EchoRequestPayload) -> None:
        echoed = payload.payload.decode("utf-8") + "!"
        self.ez_send(peer, EchoResponsePayload(echoed.encode("utf-8")))

    @lazy_wrapper(EchoResponsePayload)
    def on_echo_response(self, peer: Peer, payload: EchoResponsePayload) -> None:
        self.received_responses.append(payload.payload.decode("utf-8"))
'''


def _echo_source(cid_hex: str) -> str:
    return "```python\n" + _ECHO_SOURCE_TMPL.replace("{CID}", cid_hex) + "```"


class _EchoLLM:
    """In-file LLM double that returns the echo implementation for whatever
    community_id the compiler's prompt declares (it embeds
    ``community_id_hex=<hex>``). A local test fixture in the idiom of this
    file's ``SlowLLM`` — not the removed shared stub infrastructure."""
    model_id = "echo-double-1"

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
        marker = "community_id_hex="
        idx = user.find(marker)
        cid_hex = user[idx + len(marker):].split()[0].strip().rstrip(",.;") if idx >= 0 else ""
        return _echo_source(cid_hex)


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


@pytest.mark.asyncio
async def test_overlay_offer_verifies_the_offering_peer(tmp_path):
    """Receiving an OVERLAY_OFFER must add the offerer to verified_peers so a
    later fetch_overlay(offerer, ...) resolves it. Regression for the deployed
    adoption failure: the seeder saw the offer + called overlay_fetch_and_load
    but hit 'no peer with mid prefix ...' because it never verified the
    offering fetcher (it had only ever responded to that fetcher's inbound
    requests)."""
    from ipv8.keyvault.crypto import default_eccrypto

    ka, kb = tmp_path / "a.key", tmp_path / "b.key"
    ka.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())
    kb.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())
    svc_a, svc_b = _build_node(0, ka), _build_node(0, kb)
    await svc_a.start()
    await svc_b.start()
    try:
        sb_a = next(o for o in svc_a.overlays if isinstance(o, SeedboxCommunity))
        sb_b = next(o for o in svc_b.overlays if isinstance(o, SeedboxCommunity))
        # A knows B (so A can send the offer); B does NOT know A yet — the
        # asymmetry the deployed seeder hits.
        peer_b_for_a = Peer(sb_b.my_peer.public_key, address=sb_b.endpoint.get_address())
        sb_a.network.add_verified_peer(peer_b_for_a)
        a_mid = sb_a.my_peer.mid
        assert not any(p.mid == a_mid for p in sb_b.network.verified_peers)

        sb_a.offer_overlay(peer_b_for_a, ECHO_HASH)

        # B verifies A on receipt → A is now resolvable for a fetch-back.
        for _ in range(40):
            if any(p.mid == a_mid for p in sb_b.network.verified_peers):
                break
            await asyncio.sleep(0.05)
        assert any(p.mid == a_mid for p in sb_b.network.verified_peers)
    finally:
        await svc_a.stop()
        await svc_b.stop()


# ---------------------------------------------------------------------------
# OverlayRegistry: idempotent runtime registration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_registry_load_appends_and_is_idempotent(two_nodes):
    svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b = two_nodes
    before = len(svc_b.overlays)
    reg = OverlayRegistry(svc_b, _EchoLLM())

    inst1 = reg.load(ECHO_MD)
    assert inst1.community_id == ECHO_HASH
    assert len(svc_b.overlays) == before + 1

    inst2 = reg.load(ECHO_MD)
    assert inst2 is inst1
    assert len(svc_b.overlays) == before + 1  # still one new overlay


# ---------------------------------------------------------------------------
# Overlay observability: lifecycle events + per-demo spec archive
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_registry_archives_overlay_when_archive_dir_set(tmp_path, two_nodes):
    svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b = two_nodes
    archive_dir = tmp_path / "arch"
    reg = OverlayRegistry(svc_b, _EchoLLM(), archive_dir=archive_dir)
    reg.load(ECHO_MD, provenance="published")

    cid_hex = ECHO_HASH.hex()
    # The exact canonical bytes are archived, content-addressed by community_id.
    assert (archive_dir / f"{cid_hex}.md").read_bytes() == canonicalize_md(ECHO_MD)
    meta = json.loads((archive_dir / f"{cid_hex}.meta.json").read_text())
    assert meta["name"] == "echo"
    assert meta["identity_version"] == "1.0.0"
    assert any(p["tag"] == "published" for p in meta["provenance"])
    # The ledger records the install lifecycle event.
    events = [
        json.loads(line)["event"]
        for line in (archive_dir / "overlay_ledger.jsonl").read_text().splitlines()
    ]
    assert "install" in events


@pytest.mark.asyncio
async def test_registry_archive_disabled_when_dir_unset(two_nodes):
    svc_a, svc_b, *_ = two_nodes
    reg = OverlayRegistry(svc_b, _EchoLLM())
    assert reg._archive is None
    reg.load(ECHO_MD)  # must not raise without an archive configured


@pytest.mark.asyncio
async def test_registry_emits_lifecycle_events(two_nodes, caplog):
    svc_a, svc_b, *_ = two_nodes
    reg = OverlayRegistry(svc_b, _EchoLLM())
    with caplog.at_level(logging.INFO, logger="delftclaw.overlay.lifecycle"):
        reg.load(ECHO_MD)
    msgs = [r.getMessage() for r in caplog.records if r.name == "delftclaw.overlay.lifecycle"]
    assert any("OVERLAY compile" in m and "result=ok" in m for m in msgs)
    assert any("OVERLAY install" in m for m in msgs)


@pytest.mark.asyncio
async def test_registry_load_with_llm_source_archives_and_emits_lifecycle(
    tmp_path, two_nodes, caplog,
):
    """Boot-time stub publishes (where ``agent.cli._publish_overlays`` hands
    the registry a fenced ``*_stub.py`` source via ``llm_source=``) must still
    emit OVERLAY compile/install lifecycle lines AND write the per-demo
    archive entry with the caller's provenance. This is the path that was
    broken — the manual-registration shortcut skipped both, so the seeder
    never showed up in ``deploy.trace``'s overlay versions / lifecycle view."""
    import logging

    svc_a, svc_b, *_ = two_nodes
    archive_dir = tmp_path / "arch"
    # Empty stub LLM — would KeyError if the registry actually called it.
    # Passing ``llm_source=`` makes the registry skip the LLM round-trip
    # entirely, so this also asserts the bypass works.
    reg = OverlayRegistry(svc_b, noop_llm(), archive_dir=archive_dir)
    llm_source = _echo_source(community_id_from_md(ECHO_MD).hex())
    with caplog.at_level(logging.INFO, logger="delftclaw.overlay.lifecycle"):
        reg.load(ECHO_MD, provenance="published", llm_source=llm_source)

    cid_hex = ECHO_HASH.hex()
    # Archive .md + meta + ledger all populated, provenance is "published".
    assert (archive_dir / f"{cid_hex}.md").read_bytes() == canonicalize_md(ECHO_MD)
    meta = json.loads((archive_dir / f"{cid_hex}.meta.json").read_text())
    assert meta["name"] == "echo"
    assert any(p["tag"] == "published" for p in meta["provenance"])
    ledger_events = {
        json.loads(line)["event"]
        for line in (archive_dir / "overlay_ledger.jsonl").read_text().splitlines()
    }
    assert {"seen", "install"} <= ledger_events

    # Lifecycle stream sees compile (src=caller, no LLM) + install.
    msgs = [r.getMessage() for r in caplog.records if r.name == "delftclaw.overlay.lifecycle"]
    assert any("OVERLAY compile" in m and "result=ok" in m and "src=caller" in m for m in msgs)
    assert any("OVERLAY install" in m for m in msgs)


@pytest.mark.asyncio
async def test_received_spec_archived_even_on_compile_failure(tmp_path, two_nodes):
    svc_a, svc_b, *_ = two_nodes
    archive_dir = tmp_path / "arch"
    # Empty stub: llm.complete raises KeyError mid-compile, so no overlay is
    # produced. The descriptor must still be archived (it was 'seen' first).
    reg = OverlayRegistry(svc_b, noop_llm(), archive_dir=archive_dir)
    with pytest.raises(Exception):
        reg.load(ECHO_MD, provenance="received_from:zzz")

    cid_hex = ECHO_HASH.hex()
    assert (archive_dir / f"{cid_hex}.md").is_file()
    ledger = [
        json.loads(line)
        for line in (archive_dir / "overlay_ledger.jsonl").read_text().splitlines()
    ]
    events = {r["event"] for r in ledger}
    assert "seen" in events
    assert "compile_fail" in events


# ---------------------------------------------------------------------------
# Post-compile reliability: instance __init__ / started() raising
# ---------------------------------------------------------------------------

_RAISING_INIT_SOURCE = '''\
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver


@vp_compile
class EchoRequestPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenH"]
    names = ["payload"]


@vp_compile
class EchoResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["varlenH"]
    names = ["payload"]


class GeneratedCommunity(Community, PeerObserver):
    community_id = bytes.fromhex("cb34767cf5594a303df692d0eca46d8cd022a31a")

    def __init__(self, settings: CommunitySettings) -> None:
        # Assign the declared runtime-state slot so the compile-time validator
        # passes; raise AFTER the assignment so the failure surfaces during
        # instance __init__ execution rather than during compile.
        self.received_responses = []
        raise RuntimeError("simulated post-compile failure in __init__")

    def started(self) -> None:
        pass

    def on_peer_added(self, peer: Peer) -> None:
        pass

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    @lazy_wrapper(EchoRequestPayload)
    def on_echo_request(self, peer: Peer, payload: EchoRequestPayload) -> None:
        pass

    @lazy_wrapper(EchoResponsePayload)
    def on_echo_response(self, peer: Peer, payload: EchoResponsePayload) -> None:
        pass
'''


@pytest.mark.asyncio
async def test_post_compile_failure_is_archived_and_reraised(tmp_path, two_nodes):
    """``load`` must surface an LLM-emitted community's ``__init__`` raise as a
    clean ``compile_fail stage=post_compile`` ledger event AND a propagated
    exception — not a silent ``seen``-only archive stranding (the deployed bug
    that caused fetcher_2 to retry author_overlay_v_next three times). The
    registry's in-memory state must remain consistent (no half-installed
    instance left behind)."""
    svc_a, svc_b, *_ = two_nodes
    archive_dir = tmp_path / "arch"
    llm_source = "```python\n" + _RAISING_INIT_SOURCE + "```"
    reg = OverlayRegistry(svc_b, noop_llm(), archive_dir=archive_dir)
    with pytest.raises(RuntimeError, match="simulated post-compile failure"):
        reg.load(ECHO_MD, provenance="published", llm_source=llm_source)

    cid_hex = ECHO_HASH.hex()
    ledger = [
        json.loads(line)
        for line in (archive_dir / "overlay_ledger.jsonl").read_text().splitlines()
    ]
    # The seen event (pre-compile) is there. The post_compile fail is there.
    # The install event is NOT — because install never ran.
    by_event = {r["event"] for r in ledger}
    assert "seen" in by_event
    assert "install" not in by_event
    post_compile = [r for r in ledger if r.get("event") == "compile_fail" and r.get("stage") == "post_compile"]
    assert len(post_compile) == 1
    assert "RuntimeError" in post_compile[0]["error"]
    # In-memory state was rolled back — nothing recorded in _compiled / _instances.
    assert ECHO_HASH not in reg._instances
    assert ECHO_HASH not in reg._compiled


@pytest.mark.asyncio
async def test_post_compile_failure_async_path_archives_and_reraises(tmp_path, two_nodes):
    """Mirror for the ``aload`` async path the production overlay_author_and_publish
    tool uses. Same invariants: clean ledger event, propagated exception,
    consistent registry state."""
    svc_a, svc_b, *_ = two_nodes
    archive_dir = tmp_path / "arch"
    llm_source = "```python\n" + _RAISING_INIT_SOURCE + "```"
    reg = OverlayRegistry(svc_b, noop_llm(), archive_dir=archive_dir)
    with pytest.raises(RuntimeError, match="simulated post-compile failure"):
        await reg.aload(ECHO_MD, provenance="published", llm_source=llm_source)

    ledger = [
        json.loads(line)
        for line in (archive_dir / "overlay_ledger.jsonl").read_text().splitlines()
    ]
    post_compile = [r for r in ledger if r.get("event") == "compile_fail" and r.get("stage") == "post_compile"]
    assert len(post_compile) == 1
    assert ECHO_HASH not in reg._instances


# ---------------------------------------------------------------------------
# End-to-end: fetch + compile + register + exchange
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_remote_fetched_overlay_round_trips_a_message(two_nodes):
    svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b = two_nodes

    # Alice publishes locally.
    sb_a.publish_overlay(ECHO_MD)
    reg_a = OverlayRegistry(svc_a, _EchoLLM())
    echo_a = reg_a.load(ECHO_MD)

    # Bob fetches via the bootstrap, then compiles+registers.
    md_bytes = await asyncio.wait_for(
        sb_b.fetch_overlay(peer_a_for_b, ECHO_HASH), timeout=2.0
    )
    reg_b = OverlayRegistry(svc_b, _EchoLLM())
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


# ---------------------------------------------------------------------------
# Cancellation-resilience: the watchdog's 240s wait_for can cancel aload's
# await mid-compile. The install MUST still complete on the event loop so
# the agent's archive is consistent on the next snapshot.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_aload_shielded_install_survives_caller_cancellation(tmp_path, two_nodes):
    """Outer ``asyncio.wait_for`` cancels us mid-compile -> caller sees
    TimeoutError, but the post-compile section ran to completion on the
    event loop. Verified by: instance is in registry._instances; meta.json
    has populated identity; ``OVERLAY install`` lifecycle line was logged."""
    import logging

    class SlowLLM:
        model_id = "slow-1"
        async def acomplete(self, *a, **kw):
            await asyncio.sleep(2.0)
            return _echo_source(community_id_from_md(ECHO_MD).hex())
        def complete(self, *a, **kw):
            # Synchronous slow stub — runs inside asyncio.to_thread, so the
            # sleep doesn't block the event loop. The outer wait_for can
            # still cancel.
            import time as _time
            _time.sleep(2.0)
            return _echo_source(community_id_from_md(ECHO_MD).hex())

    svc_a, svc_b, *_ = two_nodes
    archive_dir = tmp_path / "arch"
    reg = OverlayRegistry(svc_b, SlowLLM(), archive_dir=archive_dir)

    caplog_records: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda r: caplog_records.append(r.getMessage())
    lifecycle = logging.getLogger("delftclaw.overlay.lifecycle")
    lifecycle.addHandler(handler)
    lifecycle.setLevel(logging.INFO)
    try:
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                reg.aload(ECHO_MD, provenance="published"),
                timeout=0.3,
            )
        # Let the shielded post-compile finish on the event loop.
        for _ in range(80):
            if ECHO_HASH in reg._instances:
                break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("shielded install never completed")
    finally:
        lifecycle.removeHandler(handler)

    # Install side effects all visible AFTER the caller saw a TimeoutError.
    assert ECHO_HASH in reg._instances
    meta = json.loads((archive_dir / f"{ECHO_HASH.hex()}.meta.json").read_text())
    assert meta["name"] == "echo"
    assert meta["identity_version"] == "1.0.0"
    assert any(
        "OVERLAY install" in line and ECHO_HASH.hex() in line
        for line in caplog_records
    )


@pytest.mark.asyncio
async def test_aload_authored_event_written_from_inside_shield(tmp_path, two_nodes):
    """When ``authored_event`` is passed, the version-history JSONL row is
    written from INSIDE the shield — surviving an outer cancellation. Without
    this, the publish tool's post-aload direct write would be skipped when
    the outer caller is cancelled, and v1.1 would never appear in
    version_history.md."""
    import time as _time

    class SlowLLM:
        model_id = "slow-1"
        def complete(self, *a, **kw):
            _time.sleep(2.0)
            return _echo_source(community_id_from_md(ECHO_MD).hex())

    svc_a, svc_b, *_ = two_nodes
    archive_dir = tmp_path / "arch"
    history_dir = tmp_path / "history"
    reg = OverlayRegistry(svc_b, SlowLLM(), archive_dir=archive_dir, history_dir=history_dir)
    authored_event = {
        "name": "echo", "identity_version": "1.0.0",
        "supersedes": None, "author_id": "dclaw1tester",
        "change_summary": "test row",
    }

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(
            reg.aload(ECHO_MD, provenance="published", authored_event=authored_event),
            timeout=0.3,
        )
    # Wait for shield to land.
    for _ in range(80):
        if ECHO_HASH in reg._instances:
            break
        await asyncio.sleep(0.05)

    # The authored event landed in the fleet-merged history file even though
    # the caller was cancelled.
    from protocol.version_history import HISTORY_JSONL
    rows = [
        json.loads(line)
        for line in (history_dir / HISTORY_JSONL).read_text().splitlines()
        if line.strip()
    ]
    assert any(
        r.get("name") == "echo" and r.get("identity_version") == "1.0.0"
        and r.get("author_id") == "dclaw1tester"
        for r in rows
    )


# ---------------------------------------------------------------------------
# Per-agent aload lock: two concurrent calls serialize cleanly. Defends
# against the parallel-adopt collision pattern observed on 2026-05-30.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_aload_lock_serializes_concurrent_calls(tmp_path, two_nodes):
    """Two ``asyncio.create_task(aload(...))`` calls overlap in wall-clock
    time but their compile phases must NOT interleave. Verifies a single
    aload runs end-to-end before the next begins, per the per-agent lock."""
    from protocol.compiler import community_id_from_md
    svc_a, svc_b, *_ = two_nodes

    # Two distinct overlay specs (different cids). Pre-canned stub sources
    # so the compile is fast but observable.
    md_v1 = ECHO_MD
    md_v2 = ECHO_MD + "\n\n<!-- variant -->\n"
    cid_v1 = community_id_from_md(md_v1)
    cid_v2 = community_id_from_md(md_v2)
    assert cid_v1 != cid_v2

    # _EchoLLM routes by the cid in each compile prompt, so it serves the
    # right echo source for both v1 and v2 without per-cid wiring.
    reg = OverlayRegistry(svc_b, _EchoLLM())

    # Instrument the compile entry point: record (cid_hex, t_enter, t_exit).
    # Use time.monotonic() rather than the event-loop clock — the instrumented
    # function runs inside asyncio.to_thread, where there is no event loop.
    import time as _time
    intervals: list[tuple[str, float, float]] = []
    original_compile = reg._compile_with_disk_cache
    def instrumented(md, **kw):
        cid_hex = community_id_from_md(md).hex()
        t0 = _time.monotonic()
        # Slow the compile down enough that an unlocked overlap would
        # actually overlap in wall-clock.
        _time.sleep(0.05)
        result = original_compile(md, **kw)
        t1 = _time.monotonic()
        intervals.append((cid_hex, t0, t1))
        return result
    reg._compile_with_disk_cache = instrumented

    t1 = asyncio.create_task(reg.aload(md_v1, provenance="t1"))
    t2 = asyncio.create_task(reg.aload(md_v2, provenance="t2"))
    await asyncio.gather(t1, t2)

    assert len(intervals) == 2
    # Sort by start time; the second compile must start AFTER the first ends.
    intervals.sort(key=lambda x: x[1])
    (_, _, end_first), (_, start_second, _) = intervals
    assert start_second >= end_first, (
        f"compiles overlapped: first ended at {end_first}, "
        f"second started at {start_second}"
    )
