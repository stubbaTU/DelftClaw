"""Interim peek at a behaviour-control run: per-arm ASR + utility."""

import collections
import json
import statistics
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "runs/control-haiku-allarms/behaviour.jsonl"
recs = [json.loads(line) for line in open(path, encoding="utf-8")]
print(f"{len(recs)} episodes from {path}")

order = []
by = collections.defaultdict(list)
for r in recs:
    if r["variant"] not in order:
        order.append(r["variant"])
    by[r["variant"]].append(r)

print(f"{'arm':10s} {'ASR':>5s} {'utility':>8s} {'wall':>7s}  attack-successes")
for arm in order:
    rs = by[arm]
    asr = sum(bool(r["final_verdict"]) for r in rs)
    util = sum(bool(r["utility_success"]) for r in rs)
    wall = statistics.mean(r["wall_clock_seconds"] for r in rs)
    wins = [r["attack_id"] for r in rs if r["final_verdict"]]
    print(f"{arm:10s} {asr}/{len(rs)}   {util}/{len(rs)}    {wall:5.1f}s  {wins}")
