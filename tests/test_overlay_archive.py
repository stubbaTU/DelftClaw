"""Unit tests for the per-demo overlay spec archive (version control).

Covers the content-addressed store + meta + ledger in isolation (no IPv8):
write-once dedup, canonicalization-based cid, provenance accumulation, and
that a descriptor is archivable from raw md_text even without a CompiledOverlay
(so received specs are captured even when their compile fails).
"""

from __future__ import annotations

import json
from pathlib import Path

from protocol.compiler import canonicalize_md, community_id_from_md
from protocol.overlay_archive import OverlayArchive


REPO_ROOT = Path(__file__).resolve().parent.parent
ECHO_MD = (REPO_ROOT / "protocol" / "examples" / "echo_overlay.md").read_text()
CID_HEX = community_id_from_md(ECHO_MD).hex()


def test_archive_bytes_is_write_once(tmp_path):
    archive = OverlayArchive(tmp_path)
    assert archive.archive_bytes(CID_HEX, b"hello") is True
    assert (tmp_path / f"{CID_HEX}.md").read_bytes() == b"hello"
    # Content-addressed: a second write is a no-op; original bytes preserved.
    assert archive.archive_bytes(CID_HEX, b"DIFFERENT") is False
    assert (tmp_path / f"{CID_HEX}.md").read_bytes() == b"hello"


def test_record_archives_canonical_bytes_meta_and_ledger(tmp_path):
    archive = OverlayArchive(tmp_path)
    cid = archive.record(ECHO_MD, event="seen", provenance="received_from:abc123")
    assert cid == CID_HEX
    # Archived bytes are the canonical form, not the raw text.
    assert (tmp_path / f"{CID_HEX}.md").read_bytes() == canonicalize_md(ECHO_MD)

    meta = json.loads((tmp_path / f"{CID_HEX}.meta.json").read_text())
    assert meta["community_id_hex"] == CID_HEX
    assert meta["canonical_sha1"].startswith(CID_HEX)  # cid is sha1[:20] → first 40 hex
    assert [p["tag"] for p in meta["provenance"]] == ["received_from:abc123"]

    ledger = (tmp_path / "overlay_ledger.jsonl").read_text().splitlines()
    assert len(ledger) == 1
    rec = json.loads(ledger[0])
    assert rec["event"] == "seen"
    assert rec["community_id_hex"] == CID_HEX
    assert rec["provenance"] == "received_from:abc123"


def test_repeat_appearance_accumulates_provenance_keeps_single_object(tmp_path):
    archive = OverlayArchive(tmp_path)
    archive.record(ECHO_MD, event="seen", provenance="received_from:abc")
    archive.record(ECHO_MD, event="install", provenance="published")

    meta = json.loads((tmp_path / f"{CID_HEX}.meta.json").read_text())
    assert [p["tag"] for p in meta["provenance"]] == ["received_from:abc", "published"]
    assert len(list(tmp_path.glob("*.md"))) == 1  # one content object
    assert len((tmp_path / "overlay_ledger.jsonl").read_text().splitlines()) == 2


def test_canonicalization_collapses_cosmetic_differences(tmp_path):
    archive = OverlayArchive(tmp_path)
    cid1 = archive.record(ECHO_MD, event="seen")
    cid2 = archive.record(ECHO_MD + "\n\n\n", event="seen")  # trailing newlines
    assert cid1 == cid2 == CID_HEX
    assert len(list(tmp_path.glob("*.md"))) == 1


def test_record_captures_evolution_metadata_from_identity(tmp_path):
    """supersedes / author_id / change_summary are parsed from the in-band
    # Identity block and mirrored into meta.json; authored_ts is set only when
    the agent published the spec (not when it adopted someone else's)."""
    class _Parsed:
        identity = {
            "name": "download_announce", "version": "1.0.0",
            "supersedes": "a3455e9cec3b78bc281f1c495b0a08baa733833a",
            "author_id": "dclaw1author", "change_summary": "Announce downloads",
        }

    class _Compiled:
        parsed = _Parsed()
        origin = "markdown"

    # Author side: provenance=published → authored_ts present.
    author = OverlayArchive(tmp_path / "author")
    cid = author.record(ECHO_MD, compiled=_Compiled(), event="install", provenance="published")
    meta = json.loads((tmp_path / "author" / f"{cid}.meta.json").read_text())
    assert meta["supersedes"] == "a3455e9cec3b78bc281f1c495b0a08baa733833a"
    assert meta["author_id"] == "dclaw1author"
    assert meta["change_summary"] == "Announce downloads"
    assert "authored_ts" in meta

    # Adopter side: provenance=received → same spec metadata, NO authored_ts.
    adopter = OverlayArchive(tmp_path / "adopter")
    adopter.record(ECHO_MD, compiled=_Compiled(), event="install", provenance="received_from:x")
    ameta = json.loads((tmp_path / "adopter" / f"{cid}.meta.json").read_text())
    assert ameta["author_id"] == "dclaw1author"      # describes the spec
    assert ameta["change_summary"] == "Announce downloads"
    assert "authored_ts" not in ameta                # adopter didn't author it


def test_self_authored_ids_and_has_are_cross_process(tmp_path):
    """A second OverlayArchive over the same dir sees what the first wrote —
    the cross-process bridge the watchdog snapshot relies on. self_authored_ids
    matches author_id + authored_ts (publisher only); has() tracks the .md."""
    class _Parsed:
        identity = {
            "name": "download_announce", "version": "1.0.0",
            "author_id": "dclaw1author", "change_summary": "x",
        }

    class _Compiled:
        parsed = _Parsed()
        origin = "markdown"

    # Process A authors (publishes).
    a = OverlayArchive(tmp_path / "shared")
    cid = a.record(ECHO_MD, compiled=_Compiled(), event="install", provenance="published")

    # Process B — a DIFFERENT instance over the same dir — sees it.
    b = OverlayArchive(tmp_path / "shared")
    assert b.self_authored_ids("dclaw1author") == [cid]
    assert b.has(cid) is True
    # Wrong author / unknown cid: no match.
    assert b.self_authored_ids("dclaw1someoneelse") == []
    assert b.has("00" * 20) is False


def test_self_authored_ids_excludes_adopted_overlays(tmp_path):
    """An overlay this agent ADOPTED (received_from, no authored_ts) is not
    reported as self-authored, even though its author_id is set."""
    class _Parsed:
        identity = {"name": "download_announce", "version": "1.0.0",
                    "author_id": "dclaw1author", "change_summary": "x"}

    class _Compiled:
        parsed = _Parsed()
        origin = "markdown"

    adopter = OverlayArchive(tmp_path / "adopter")
    cid = adopter.record(ECHO_MD, compiled=_Compiled(), event="install",
                         provenance="received_from:peer")
    # The adopter holds it (has) but did NOT author it (no authored_ts for them).
    assert adopter.has(cid) is True
    assert adopter.self_authored_ids("dclaw1author") == []


def test_append_authored_event_writes_once(tmp_path):
    archive = OverlayArchive(tmp_path)
    archive.append_authored_event(
        "ab" * 20, name="download_announce", identity_version="1.0.0",
        supersedes=None, author_id="dclaw1author", change_summary="x",
    )
    lines = (tmp_path / "overlay_ledger.jsonl").read_text().splitlines()
    rec = json.loads(lines[-1])
    assert rec["event"] == "authored"
    assert rec["author_id"] == "dclaw1author"
    assert rec["supersedes"] is None


def test_record_with_compiled_captures_name_version_model(tmp_path):
    class _Parsed:
        identity = {"name": "echo", "version": "1.0.0"}

    class _Compiled:
        parsed = _Parsed()
        origin = "markdown"

    archive = OverlayArchive(tmp_path)
    archive.record(
        ECHO_MD, compiled=_Compiled(), event="install",
        provenance="published", model_id="stub-1",
    )
    meta = json.loads((tmp_path / f"{CID_HEX}.meta.json").read_text())
    assert meta["name"] == "echo"
    assert meta["identity_version"] == "1.0.0"
    assert meta["model_id"] == "stub-1"
    assert meta["origin"] == "markdown"

    rec = json.loads((tmp_path / "overlay_ledger.jsonl").read_text().splitlines()[-1])
    assert rec["name"] == "echo"
    assert rec["identity_version"] == "1.0.0"
    assert rec["model_id"] == "stub-1"


def test_history_dir_mirrors_authored_events_and_renders_markdown(tmp_path):
    """When history_dir is set, append_authored_event writes BOTH the per-agent
    ledger AND the fleet-wide version_history.{jsonl,md}. Two archives over
    different per-agent dirs but the same history_dir produce a merged
    timeline — the deployed shape for the per-scenario thesis artifact."""
    history = tmp_path / "history"
    a = OverlayArchive(tmp_path / "agent_a", history_dir=history)
    b = OverlayArchive(tmp_path / "agent_b", history_dir=history)

    a.append_authored_event(
        "aa" * 20,
        name="download_announce", identity_version="1.0.0",
        supersedes=None, author_id="dclaw1alice",
        change_summary="Announce a completed download",
    )
    b.append_authored_event(
        "bb" * 20,
        name="download_announce", identity_version="1.1.0",
        supersedes="aa" * 20, author_id="dclaw1bob",
        change_summary="Adds sha256 checksum",
    )

    # Per-agent ledger keeps working untouched.
    for sub in ("agent_a", "agent_b"):
        ledger = (tmp_path / sub / "overlay_ledger.jsonl").read_text().splitlines()
        assert any(json.loads(line)["event"] == "authored" for line in ledger)

    # Merged fleet history exists with BOTH events, plus a rendered markdown.
    fleet_jsonl = history / "version_history.jsonl"
    fleet_md = history / "version_history.md"
    assert fleet_jsonl.is_file() and fleet_md.is_file()

    events = [json.loads(l) for l in fleet_jsonl.read_text().splitlines()]
    versions = [e["identity_version"] for e in events]
    assert set(versions) == {"1.0.0", "1.1.0"}

    md = fleet_md.read_text()
    assert "## download_announce" in md
    assert "1.0.0" in md and "1.1.0" in md
    assert "Adds sha256 checksum" in md


def test_is_installed_distinguishes_seen_from_installed(tmp_path):
    """``is_installed`` must reflect "install completed", not just "bytes
    archived." A hung post-compile leaves a .md plus a seen-only meta.json
    with empty identity; the agent must be able to retry the adopt rather
    than treating the stranded spec as already-loaded. Verified by the
    2026-05-30 ~19:07 deployed incident."""
    archive = OverlayArchive(tmp_path)
    cid_hex = "ab" * 20
    # Nothing on disk yet.
    assert archive.has(cid_hex) is False
    assert archive.is_installed(cid_hex) is False
    # Seen-only: .md present, but meta has empty identity (the shape
    # ``_archive_seen`` writes before compile/install run).
    (tmp_path / f"{cid_hex}.md").write_text("# Identity\n", encoding="utf-8")
    (tmp_path / f"{cid_hex}.meta.json").write_text(
        json.dumps({"community_id_hex": cid_hex, "name": "", "identity_version": ""}),
        encoding="utf-8",
    )
    assert archive.has(cid_hex) is True
    assert archive.is_installed(cid_hex) is False    # the critical line
    # Install completes: meta gains a populated name + identity_version.
    (tmp_path / f"{cid_hex}.meta.json").write_text(
        json.dumps({
            "community_id_hex": cid_hex,
            "name": "download_announce", "identity_version": "1.0.0",
        }),
        encoding="utf-8",
    )
    assert archive.is_installed(cid_hex) is True
