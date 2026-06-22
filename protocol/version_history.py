"""Fleet-wide, append-only version history of agent-authored overlays.

The per-agent ``overlay_archive/overlay_ledger.jsonl`` is good for forensics on
ONE agent (what they saw, installed, authored). But the thesis needs a single
**scenario-wide timeline** of every protocol version any agent introduced —
that's the artifact you paste into the writeup: who authored what, when, and
which version it superseded.

This module owns that fleet-merged artifact:

  * ``append_history_event(history_dir, event)`` — atomic JSON-line append to
    ``<history_dir>/version_history.jsonl``. Called by every agent's
    ``OverlayArchive.append_authored_event``. Cross-process safe (atomic file
    open in append mode + a tempfile-renamed write for the rendered markdown).
  * ``render_markdown_summary(history_dir) -> str`` — groups events by overlay
    name, follows ``supersedes`` chains, renders one table per name. The
    artifact ``make trace`` inlines and ``make demo`` bundles.

Both functions are pure (no IPv8, no agent state) and tolerant of partial
input: a missing dir / empty ledger / unparsable lines render as an empty
summary rather than raising, so a failed evolution run still produces a
readable artifact.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HISTORY_JSONL = "version_history.jsonl"
HISTORY_MD = "version_history.md"

_log = logging.getLogger(__name__)


def append_history_event(history_dir: Path | str, event: dict[str, Any]) -> None:
    """Append one JSON-line authored event to the fleet-wide history file.

    Stamps ``ts`` if missing. Best-effort: a failed write logs a warning (so a
    deployment misconfig — e.g. parent dir owned by root with the service user
    lacking write — is visible in the journal) but never raises. The per-agent
    ledger is the source of truth; this is a derived convenience artifact and
    must not break the agent.
    """
    path = Path(history_dir)
    try:
        path.mkdir(parents=True, exist_ok=True)
        line = dict(event)
        line.setdefault("ts", time.time())
        with open(path / HISTORY_JSONL, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(line, default=str) + "\n")
    except OSError as exc:
        _log.warning("version_history append failed at %s: %s", path, exc)


def read_history(history_dir: Path | str) -> list[dict[str, Any]]:
    """Read every authored event from the fleet history, oldest first.

    Returns ``[]`` if the file is missing or empty; skips malformed lines so a
    partially-corrupted ledger still yields a usable summary.
    """
    path = Path(history_dir) / HISTORY_JSONL
    out: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    out.sort(key=lambda e: float(e.get("ts") or 0.0))
    return out


def render_markdown_summary(history_dir: Path | str) -> str:
    """Render the fleet history as one markdown table per overlay ``name``.

    Within each name, rows are ordered oldest → newest by ``ts`` and the
    ``supersedes`` cid is shown as a short prefix (or ``—`` for roots). Names
    are output alphabetically so the artifact is stable across runs. Returns
    an explicit ``"(no authored events recorded)"`` line when the history is
    empty so the artifact is never silently missing.
    """
    events = read_history(history_dir)
    if not events:
        return "# Overlay version history\n\n(no authored events recorded)\n"

    by_name: dict[str, list[dict[str, Any]]] = {}
    for ev in events:
        by_name.setdefault(ev.get("name") or "(unknown)", []).append(ev)

    lines: list[str] = ["# Overlay version history", ""]
    for name in sorted(by_name):
        rows = by_name[name]
        # Stable name-level sort by ts (already sorted globally, but the
        # group split could re-order if two names interleave).
        rows.sort(key=lambda e: float(e.get("ts") or 0.0))
        lines += [f"## {name}", ""]
        lines += ["| Version | Author | Authored at | cid | Supersedes | Change summary |",
                  "|---|---|---|---|---|---|"]
        for ev in rows:
            version = str(ev.get("identity_version") or "?")
            author = str(ev.get("author_id") or "")
            ts = ev.get("ts")
            try:
                authored_at = datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat(timespec="seconds")
            except (TypeError, ValueError):
                authored_at = "?"
            cid = str(ev.get("community_id_hex") or "")[:12]
            sup = str(ev.get("supersedes") or "")
            sup_cell = sup[:12] if sup else "—"
            summary = str(ev.get("change_summary") or "").replace("|", "\\|").replace("\n", " ").strip()
            lines.append(
                f"| {version} | {author[:18]} | {authored_at} | {cid} | {sup_cell} | {summary} |"
            )
        lines.append("")
    return "\n".join(lines) + ("\n" if not lines[-1].endswith("\n") else "")


def write_markdown_summary(history_dir: Path | str) -> Path | None:
    """Render + atomically write ``version_history.md`` next to the JSONL.

    Returns the written path, or ``None`` if the directory doesn't exist and
    can't be created (best-effort, like ``append_history_event``).
    """
    path = Path(history_dir)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _log.warning("version_history mkdir failed at %s: %s", path, exc)
        return None
    md = render_markdown_summary(path)
    target = path / HISTORY_MD
    try:
        fd, tmp = tempfile.mkstemp(prefix=".version_history_", suffix=".md.tmp", dir=str(path))
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(md)
        os.replace(tmp, target)
        return target
    except OSError as exc:
        _log.warning("version_history write failed at %s: %s", target, exc)
        return None
