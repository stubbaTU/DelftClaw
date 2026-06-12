"""Inspect a kept live run's REAL artifacts (read-only).

Three questions:
  1. What did the agent actually do? -> the claude SESSION JSONL
     (``.claude/projects/<hash>/<sessionId>.jsonl``).
  2. Did the agent ever issue a ``tools/call`` (vs just handshake/tools-list)?
     -> the harness MCP LOG (``.cache/.../mcp-logs-harness/*.jsonl``).
  3. Does our trace.py parse the real session schema? -> we run it + dump raw.

Usage: .venv/bin/python scripts/peek_jsonl.py [runs/<run-id>]
"""

import json
import os
import sys

run_dir = sys.argv[1] if len(sys.argv) > 1 else "runs/live-smoke3"

sessions, harness_logs = [], []
for root, _dirs, names in os.walk(f"{run_dir}/homes"):
    for name in names:
        if not name.endswith(".jsonl"):
            continue
        full = os.path.join(root, name)
        if f"{os.sep}.claude{os.sep}projects{os.sep}" in full:
            sessions.append(full)
        elif "mcp-logs-harness" in full:
            harness_logs.append(full)
sessions.sort()
harness_logs.sort()
print(f"=== {len(sessions)} claude session JSONLs, {len(harness_logs)} harness MCP logs ===")


def dump_raw(path, label):
    print(f"\n=== {label} ===\n{path}")
    for i, line in enumerate(open(path, encoding="utf-8")):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception as exc:
            print(f"[{i}] UNPARSEABLE: {exc}")
            continue
        if isinstance(rec, dict):
            print(f"[{i}] keys={list(rec.keys())}")
            print("     " + json.dumps(rec)[:600])
        else:
            print(f"[{i}] {type(rec).__name__}: {json.dumps(rec)[:300]}")


if sessions:
    dump_raw(sessions[0], "CLAUDE SESSION JSONL (what the agent did)")
    sys.path.insert(0, ".")
    from redteam_ablation.live.trace import parse_session_jsonl  # noqa: E402

    tr = parse_session_jsonl(sessions[0])
    print("\n--- trace.py says ---")
    print(f"  tool_calls: {[(c.name, c.input) for c in tr.tool_calls]}")
    print(f"  final_text: {tr.final_text!r}")

if harness_logs:
    print("\n\n=== HARNESS MCP LOG: JSON-RPC methods (did the agent call tools?) ===")
    print(harness_logs[0])
    for i, line in enumerate(open(harness_logs[0], encoding="utf-8")):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            print(f"[{i}] (non-json) {line[:120]}")
            continue
        # MCP log lines wrap a JSON-RPC message; surface method/direction.
        method = None
        if isinstance(rec, dict):
            method = rec.get("method")
            inner = rec.get("message") or rec.get("payload") or rec.get("data")
            if method is None and isinstance(inner, dict):
                method = inner.get("method")
        print(f"[{i}] method={method!r}  {json.dumps(rec)[:200]}")
