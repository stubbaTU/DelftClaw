"""Tests for deploy.trace's overlay monitoring + version-control rendering.

Exercises the reporting logic deterministically without systemd/journalctl:
the journal-line parser (compile/install histogram) is fed canned lines, and
the version grouper/drift detector runs against a real OverlayArchive layout in
a tmp STATE_ROOT.
"""

from __future__ import annotations

import json
from pathlib import Path

import deploy.trace as trace
from protocol.compiler import community_id_from_md
from protocol.overlay_archive import OverlayArchive


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTENT_MD = (REPO_ROOT / "protocol" / "examples" / "content_community.md").read_text()


class _FakeCompiled:
    """Minimal stand-in for CompiledOverlay (only the fields the archive reads)."""

    def __init__(self, name: str, version: str, origin: str = "markdown") -> None:
        self.parsed = type("P", (), {"identity": {"name": name, "version": version}})()
        self.origin = origin


def _archive_for(base: Path, scenario: str, agent: str) -> OverlayArchive:
    return OverlayArchive(base / scenario / agent / "overlay_archive")


# ---------------------------------------------------------------------------
# Journal lifecycle parsing
# ---------------------------------------------------------------------------

def test_overlay_lifecycle_histogram_parses_journal(monkeypatch):
    lines = [
        "May 28 10:00:00 host python[1]: OVERLAY compile cid=aaaa result=ok "
        "name=echo version=1.0.0 origin=markdown msgs=2 vectors=6 src=llm model=stub ms=12",
        "May 28 10:00:01 host python[1]: OVERLAY install cid=aaaa name=echo "
        "version=1.0.0 origin=markdown",
        "May 28 10:00:02 host python[2]: OVERLAY compile cid=bbbb result=fail "
        "stage=sandbox src=cache_hit model=stub ms=3 err=boom went wrong",
        "an unrelated journal line",
        "May 28 10:00:03 host python[2]: IPv8 send msg=Foo peer=zz",  # not an overlay line
    ]
    monkeypatch.setattr(trace, "_journal_lines", lambda scenario, tail=None: lines)
    hist = trace._overlay_lifecycle_histogram("demo")
    assert hist[("compile", "ok")] == 1
    assert hist[("compile", "fail")] == 1
    assert hist[("install", "")] == 1
    assert hist[("src", "llm")] == 1
    assert hist[("src", "cache_hit")] == 1
    # The IPv8 line and prose line must not leak into the overlay histogram.
    assert sum(hist.values()) == 5


def test_render_overlay_lifecycle_smoke(monkeypatch, capsys):
    monkeypatch.setattr(trace, "_journal_lines", lambda scenario, tail=None: [])
    trace._render_overlay_lifecycle(
        trace._overlay_lifecycle_histogram("demo"), trace._recent_overlay_events("demo")
    )
    out = capsys.readouterr().out
    assert "overlay lifecycle" in out


# ---------------------------------------------------------------------------
# Version archive grouping + drift detection
# ---------------------------------------------------------------------------

def test_overlay_versions_groups_holders_no_drift(tmp_path, monkeypatch):
    monkeypatch.setattr(trace, "STATE_ROOT", tmp_path)
    compiled = _FakeCompiled("content_community", "1.0.0")
    for agent, prov in (("seeder", "published"), ("fetcher_1", "received_from:seeder")):
        _archive_for(tmp_path, "demo", agent).record(
            CONTENT_MD, compiled=compiled, event="install", provenance=prov, model_id="stub",
        )

    agents = trace._agents_with_archive("demo")
    assert set(agents) == {"seeder", "fetcher_1"}

    by_cid, drift = trace._overlay_versions("demo", agents)
    assert len(by_cid) == 1
    (cid, entry), = by_cid.items()
    assert cid == community_id_from_md(CONTENT_MD).hex()
    assert entry["name"] == "content_community"
    assert entry["holders"] == {"seeder", "fetcher_1"}
    assert drift == []

    tail = trace._overlay_ledger_tail("demo", agents)
    assert any("install" in line for line in tail)


def test_overlay_versions_detects_drift(tmp_path, monkeypatch):
    monkeypatch.setattr(trace, "STATE_ROOT", tmp_path)
    compiled = _FakeCompiled("content_community", "1.0.0")
    # Same overlay NAME, two byte-different specs → two distinct community_ids.
    spec_a = CONTENT_MD
    spec_b = CONTENT_MD.replace(
        "Search the local content index", "Search the catalogue"
    )
    assert community_id_from_md(spec_a) != community_id_from_md(spec_b)
    _archive_for(tmp_path, "demo", "seeder").record(
        spec_a, compiled=compiled, event="install", provenance="published",
    )
    _archive_for(tmp_path, "demo", "fetcher_1").record(
        spec_b, compiled=compiled, event="install", provenance="received_from:x",
    )

    by_cid, drift = trace._overlay_versions("demo", trace._agents_with_archive("demo"))
    assert len(by_cid) == 2
    assert len(drift) == 1
    assert "content_community" in drift[0]


def test_render_overlay_versions_smoke_empty(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(trace, "STATE_ROOT", tmp_path)
    trace._render_overlay_versions("demo")
    out = capsys.readouterr().out
    assert "overlay versions" in out


# ---------------------------------------------------------------------------
# Tool-call histogram — requires journalctl ``-o with-unit`` output
# ---------------------------------------------------------------------------

def test_tool_histogram_attributes_calls_to_agents(monkeypatch):
    """Regression guard: ``_tool_histogram`` MUST request ``-o with-unit`` so
    the unit name (and therefore the agent name) is parseable on every line.

    The previous ``-o short-iso --output-fields=UNIT,MESSAGE`` invocation
    silently dropped the unit (``--output-fields`` is only honoured by
    verbose/json formats), so every call collapsed to ``agent="?"`` and the
    renderer printed ``"no tool calls in journal"`` for every agent even when
    the MCP service was dispatching dozens per turn (observed on the
    deployed file_share scenario)."""
    import subprocess

    journal_lines = "\n".join([
        # Same shape ``-o with-unit`` produces on the VPS:
        "Fri 2026-05-29 08:01:25 UTC srv1665973 delftclaw-mcp@file_share-fetcher_1.service[438081]: "
        "08:01:25 delftclaw.agent.tools INFO TOOL call name=content_search_and_fetch args={\"query\": \"calculus\"}",
        "Fri 2026-05-29 08:05:22 UTC srv1665973 delftclaw-mcp@file_share-fetcher_2.service[438194]: "
        "08:05:22 delftclaw.agent.tools INFO TOOL call name=content_search_and_fetch args={\"query\": \"pancakes\"}",
        "Fri 2026-05-29 08:05:30 UTC srv1665973 delftclaw-watchdog@file_share-seeder.service[440000]: "
        "08:05:30 delftclaw.agent.tools INFO TOOL call name=torrent_stats args={}",
        # noise lines that must not be counted
        "Fri 2026-05-29 08:05:31 UTC srv1665973 systemd[1]: Reloading.",
        "Fri 2026-05-29 08:05:32 UTC srv1665973 delftclaw-mcp@file_share-fetcher_1.service[438081]: "
        "08:05:32 delftclaw.communication.wire INFO IPv8 send msg=SEARCH_REQUEST peer=...",
    ])

    captured_cmd: list[list[str]] = []

    class _FakeProc:
        stdout = journal_lines

    def fake_run(cmd, capture_output=False, text=False):
        captured_cmd.append(cmd)
        return _FakeProc()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = trace._tool_histogram("file_share")

    # Load-bearing: we MUST request ``-o with-unit`` to make the unit name
    # appear on every line. Anything else (short, short-iso) leaves it off.
    assert "-o" in captured_cmd[0] and "with-unit" in captured_cmd[0], captured_cmd[0]

    assert result["fetcher_1"]["content_search_and_fetch"] == 1
    assert result["fetcher_2"]["content_search_and_fetch"] == 1
    assert result["seeder"]["torrent_stats"] == 1
    # "?" bucket stays empty — every call got attributed.
    assert "?" not in result or sum(result["?"].values()) == 0


def test_supersedes_chain_is_evolution_not_drift(tmp_path, monkeypatch):
    """Two cids for one overlay name linked by supersedes = intentional
    evolution, NOT drift. The version chain orders oldest -> newest."""
    monkeypatch.setattr(trace, "STATE_ROOT", tmp_path)

    v1_cid = "a3455e9cec3b78bc281f1c495b0a08baa733833a"
    v2_cid = "b4566f0ded4c89cd392f2d5a6c1b19cbb844944b"

    def _write(agent, cid, version, supersedes, author):
        adir = tmp_path / "demo" / agent / "overlay_archive"
        adir.mkdir(parents=True, exist_ok=True)
        (adir / f"{cid}.meta.json").write_text(json.dumps({
            "community_id_hex": cid, "name": "chat", "identity_version": version,
            "supersedes": supersedes, "author_id": author, "change_summary": "x",
            "provenance": [{"ts": 1, "tag": "published"}],
        }))

    _write("alice", v1_cid, "1.0.0", None, "dclaw1alice")
    _write("alice", v2_cid, "1.1.0", v1_cid, "dclaw1alice")
    _write("bob", v2_cid, "1.1.0", v1_cid, "dclaw1alice")

    agents = trace._agents_with_archive("demo")
    by_cid, drift = trace._overlay_versions("demo", agents)
    assert drift == []  # linked by supersedes → not drift
    chains = trace._version_chains(by_cid)
    assert chains["chat"] == [v1_cid, v2_cid]  # oldest → newest


def test_unlinked_same_name_cids_are_drift(tmp_path, monkeypatch):
    """Two cids for one name with NO supersedes link = genuine drift."""
    monkeypatch.setattr(trace, "STATE_ROOT", tmp_path)
    for agent, cid in (("alice", "aa" * 20), ("bob", "bb" * 20)):
        adir = tmp_path / "demo" / agent / "overlay_archive"
        adir.mkdir(parents=True, exist_ok=True)
        (adir / f"{cid}.meta.json").write_text(json.dumps({
            "community_id_hex": cid, "name": "chat", "identity_version": "1.0.0",
            "supersedes": None, "author_id": "", "change_summary": "",
            "provenance": [],
        }))
    by_cid, drift = trace._overlay_versions("demo", trace._agents_with_archive("demo"))
    assert len(drift) == 1
    assert "chat" in drift[0]


def test_overlay_versions_skips_empty_identity_meta(tmp_path, monkeypatch):
    """compile_fail and post-compile-stranded cids leave a meta.json with empty
    name/identity_version (only the ``seen`` event ran). The trace's ``overlay
    versions`` view must skip them — they belong in the lifecycle totals and
    overlay ledger sections, not in the human-facing version list, where they
    used to render as ``(unknown) v?`` clutter."""
    monkeypatch.setattr(trace, "STATE_ROOT", tmp_path)
    # One fully-installed overlay (legitimate row).
    compiled = _FakeCompiled("content_community", "1.0.0")
    _archive_for(tmp_path, "demo", "seeder").record(
        CONTENT_MD, compiled=compiled, event="install", provenance="published", model_id="stub",
    )
    # One stranded meta.json with empty name/version (compile-fail leftover).
    adir = tmp_path / "demo" / "fetcher_2" / "overlay_archive"
    adir.mkdir(parents=True, exist_ok=True)
    stranded_cid = "ab" * 20
    (adir / f"{stranded_cid}.md").write_bytes(b"stub")
    (adir / f"{stranded_cid}.meta.json").write_text(json.dumps({
        "community_id_hex": stranded_cid,
        "canonical_sha1": stranded_cid + "00" * 20,
        "name": "",
        "identity_version": "",
        "provenance": [{"tag": "published"}],
    }))

    by_cid, drift = trace._overlay_versions("demo", trace._agents_with_archive("demo"))
    # Only the legitimate install survives. The stranded cid is filtered out.
    assert stranded_cid not in by_cid
    assert len(by_cid) == 1
    (only_cid, entry), = by_cid.items()
    assert entry["name"] == "content_community"
    assert drift == []


def test_authored_events_surface_in_evolution_section(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(trace, "STATE_ROOT", tmp_path)
    adir = tmp_path / "demo" / "alice" / "overlay_archive"
    adir.mkdir(parents=True, exist_ok=True)
    (adir / "overlay_ledger.jsonl").write_text(json.dumps({
        "ts": 100, "event": "authored", "community_id_hex": "ab" * 20,
        "name": "download_announce", "identity_version": "1.0.0",
        "supersedes": None, "author_id": "dclaw1alice",
        "change_summary": "Announce a completed download",
    }) + "\n")
    events = trace._overlay_authored_events("demo", ["alice"])
    assert len(events) == 1
    assert "alice" in events[0] and "download_announce" in events[0]
    assert "Announce a completed download" in events[0]


def test_overlay_lifecycle_renders_caller_source(monkeypatch, capsys):
    """Regression guard for the v2 ``src=caller`` rendering. Before the fix,
    only ``cache_hit`` and ``llm`` were rendered; ``caller`` compiles (the
    seeder's stub-source publish path) were silently dropped from the
    summary line so the install count looked inconsistent with the source
    split."""
    lines = [
        "May 29 host python[1]: OVERLAY compile cid=aa result=ok name=x version=1 origin=markdown "
        "msgs=2 vectors=2 src=caller model=stub-1 ms=3",
        "May 29 host python[1]: OVERLAY install cid=aa name=x version=1 origin=markdown",
    ]
    monkeypatch.setattr(trace, "_journal_lines", lambda scenario, tail=None: lines)
    trace._render_overlay_lifecycle(
        trace._overlay_lifecycle_histogram("demo"), trace._recent_overlay_events("demo")
    )
    out = capsys.readouterr().out
    assert "1 caller" in out
