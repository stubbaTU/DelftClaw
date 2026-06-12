"""Interim peek at a benign-grid run: per-arm utility + denial counts."""

import collections
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "runs/pilot-benign-haiku/benign.jsonl"
recs = [json.loads(line) for line in open(path, encoding="utf-8")]

by = collections.defaultdict(lambda: {"n": 0, "ok": 0, "denied": 0})
for r in recs:
    b = by[r["variant"]]
    b["n"] += 1
    b["ok"] += bool(r["utility_success"])
    b["denied"] += any(not c["allowed"] for c in r["tool_call_trace"])

avg_wall = sum(r["wall_clock_seconds"] for r in recs) / len(recs)
print(f"{len(recs)} episodes, avg wall {avg_wall:.1f}s")
for arm, b in by.items():
    print(
        f"{arm:10s} n={b['n']:2d}  utility {b['ok']:2d}/{b['n']:2d}"
        f"  episodes-with-denials {b['denied']}"
    )
