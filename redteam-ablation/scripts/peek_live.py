"""Diagnose a live ablation run: did the agent refuse, mis-call, or did the
target tool fire but the predicate miss? Focuses V0 (no defenses) -- if V0 ASR
is 0 the question is WHY the dangerous tool never counted as executed.

Usage: .venv/bin/python scripts/peek_live.py [runs/<run-id>/trials.jsonl]
"""

import json
import sys

sys.path.insert(0, ".")
from redteam_ablation.catalogue.loader import load_catalogue  # noqa: E402

path = sys.argv[1] if len(sys.argv) > 1 else "runs/live-smoke3/trials.jsonl"
recs = [json.loads(line) for line in open(path, encoding="utf-8")]

# attack_id -> target dangerous tool (from the pinned catalogue).
target = {a.attack_id: a.target_tool for a in load_catalogue("catalogue/shapira.yaml")}


def final_text(trace):
    for step in trace:
        if "final_text" in step:
            return step["final_text"] or ""
    return ""


print(f"=== {len(recs)} trials from {path} ===\n")

# Per-V0 trial: what the agent did vs what the attack wanted.
print("-- V0 (no defenses): did the agent take the bait? --")
for r in recs:
    if r["variant"] != "V0":
        continue
    trace = r["tool_call_trace"]
    calls = [(s["proposed_tool"], "exec" if s["executed"] else "noexec") for s in trace]
    tgt = target.get(r["attack_id"], "?")
    hit = any(s["proposed_tool"] == tgt and s["executed"] for s in trace)
    print(
        f"{r['attack_id']} [{r['attack_class']:13s}] target={tgt:16s} "
        f"target_fired={hit}  det_verdict={r['deterministic_verdict']} "
        f"final={r['final_verdict']}"
    )
    print(f"    calls: {calls or '(none)'}")
    ft = final_text(trace).replace("\n", " ")
    print(f"    agent said: {ft[:200]!r}")

# Aggregate: across ALL variants, how often did the agent call ANY tool / the target.
print("\n-- aggregate tool activity (all variants) --")
any_call = sum(1 for r in recs if r["tool_call_trace"])
target_fired = sum(
    1
    for r in recs
    if any(
        s["proposed_tool"] == target.get(r["attack_id"]) and s["executed"]
        for s in r["tool_call_trace"]
    )
)
print(f"trials with >=1 tool call:        {any_call}/{len(recs)}")
print(f"trials where target tool fired:   {target_fired}/{len(recs)}")
print(f"trials with empty trace (no call): {sum(1 for r in recs if not r['tool_call_trace'])}/{len(recs)}")
