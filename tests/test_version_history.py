"""Tests for protocol.version_history — the fleet-merged per-scenario artifact.

The per-agent overlay_ledger.jsonl covers forensics for ONE agent. The thesis
needs a single fleet-wide timeline of every protocol version any agent
introduced. This module is small but load-bearing: it produces the
``version_history.{jsonl,md}`` artifact bundled with ``make demo`` and inlined
by ``make trace``. Pure-Python, no IPv8 or LLM needed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from protocol.version_history import (
    HISTORY_JSONL,
    HISTORY_MD,
    append_history_event,
    read_history,
    render_markdown_summary,
    write_markdown_summary,
)


def test_two_agents_writing_to_same_dir_merge_in_order(tmp_path):
    """The deployed shape: every agent's archive points at the same
    history_dir; appends from different processes interleave but ts ordering
    means read_history returns them oldest -> newest."""
    h = tmp_path / "history"
    # fetcher_1 publishes v1.0.0 first.
    append_history_event(h, {
        "ts": 100.0, "event": "authored",
        "community_id_hex": "aa" * 20,
        "name": "download_announce", "identity_version": "1.0.0",
        "supersedes": None, "author_id": "dclaw1alice",
        "change_summary": "Announce a completed download",
    })
    # fetcher_2 publishes v1.1.0 with supersedes.
    append_history_event(h, {
        "ts": 200.0, "event": "authored",
        "community_id_hex": "bb" * 20,
        "name": "download_announce", "identity_version": "1.1.0",
        "supersedes": "aa" * 20, "author_id": "dclaw1bob",
        "change_summary": "Adds sha256 checksum",
    })

    events = read_history(h)
    assert [e["identity_version"] for e in events] == ["1.0.0", "1.1.0"]
    assert events[1]["supersedes"] == "aa" * 20
    # JSONL is the on-disk source of truth.
    raw = (h / HISTORY_JSONL).read_text(encoding="utf-8").splitlines()
    assert len(raw) == 2
    assert json.loads(raw[0])["author_id"] == "dclaw1alice"


def test_render_markdown_groups_by_name_with_chain(tmp_path):
    """Markdown render groups by overlay name and orders within group by ts —
    the rendered chain order the thesis artifact will show."""
    h = tmp_path / "history"
    for ts, ver, sup, author, summary in [
        (100.0, "1.0.0", None, "dclaw1alice", "v1 baseline"),
        (200.0, "1.1.0", "aa" * 20, "dclaw1bob", "v1.1 adds field"),
    ]:
        append_history_event(h, {
            "ts": ts, "event": "authored",
            "community_id_hex": ("aa" if ver == "1.0.0" else "bb") * 20,
            "name": "download_announce", "identity_version": ver,
            "supersedes": sup, "author_id": author,
            "change_summary": summary,
        })
    md = render_markdown_summary(h)
    assert "## download_announce" in md
    # Two rows, v1 before v1.1.
    rows = [l for l in md.splitlines() if l.startswith("| 1.")]
    assert len(rows) == 2
    assert rows[0].startswith("| 1.0.0 ")
    assert rows[1].startswith("| 1.1.0 ")
    # The v1.1 row mentions the v1.0.0 cid as supersedes (12-char prefix).
    assert "aaaaaaaaaaaa" in rows[1]
    assert "v1.1 adds field" in rows[1]


def test_render_handles_empty_and_missing_history(tmp_path):
    """A failed evolution run must still produce a readable artifact."""
    # Missing dir entirely.
    assert "no authored events" in render_markdown_summary(tmp_path / "ghost")
    # Empty dir.
    empty = tmp_path / "empty"
    empty.mkdir()
    assert "no authored events" in render_markdown_summary(empty)


def test_write_markdown_summary_is_atomic_and_readable(tmp_path):
    """write_markdown_summary writes via tempfile+rename so an interrupted
    render never leaves the demo with a half-written .md."""
    h = tmp_path / "history"
    append_history_event(h, {
        "ts": 1.0, "event": "authored",
        "community_id_hex": "cc" * 20,
        "name": "echo", "identity_version": "1.0.0",
        "supersedes": None, "author_id": "x",
        "change_summary": "first",
    })
    target = write_markdown_summary(h)
    assert target is not None
    assert target == h / HISTORY_MD
    content = target.read_text(encoding="utf-8")
    assert content.startswith("# Overlay version history")
    assert "## echo" in content


def test_append_logs_warning_when_parent_unwritable(tmp_path, caplog):
    """The deployed bug shape: ``/var/lib/delftclaw/<scenario>`` exists but is
    owned by root, the service user can't open ``version_history.jsonl`` for
    append, the OSError is swallowed silently, and the fleet artifact never
    appears. The fix preserves best-effort semantics (no raise) but logs a
    warning so the failure is diagnosable from the journal."""
    import logging
    import os
    import stat

    if os.geteuid() == 0:
        pytest.skip("root bypasses POSIX write perms")
    locked = tmp_path / "locked"
    locked.mkdir()
    os.chmod(locked, stat.S_IRUSR | stat.S_IXUSR)  # 0500 — read+exec, no write
    try:
        with caplog.at_level(logging.WARNING, logger="protocol.version_history"):
            append_history_event(locked, {
                "ts": 1.0, "event": "authored",
                "community_id_hex": "aa" * 20,
                "name": "x", "identity_version": "1",
            })
        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert warnings, "expected a warning on unwritable parent"
        assert any("version_history" in r.getMessage() for r in warnings)
    finally:
        os.chmod(locked, stat.S_IRWXU)


def test_render_tolerates_malformed_lines(tmp_path):
    """A corrupted JSON line (truncated, partial write) must not crash the
    render. Skipped silently."""
    h = tmp_path / "history"
    h.mkdir()
    (h / HISTORY_JSONL).write_text(
        '{"ts": 1, "event": "authored", "name": "x", "identity_version": "1"}\n'
        '{ this is not json\n'
        '{"ts": 2, "event": "authored", "name": "x", "identity_version": "2"}\n',
        encoding="utf-8",
    )
    events = read_history(h)
    assert [e["identity_version"] for e in events] == ["1", "2"]
