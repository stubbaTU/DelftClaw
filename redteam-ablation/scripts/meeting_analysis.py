"""Deep peek at a benign-grid run for the 2026-06-12 meeting prep.

Beyond peek_benign.py: audit flags, per-arm latency, tool-call volume,
per-task utility concordance vs V0, and the conditioned ALR cells with
Wilson bounds (via the package's own metrics.alr).
"""

import collections
import json
import statistics
import sys

sys.path.insert(0, ".")
from redteam_ablation.metrics.alr import alr_summary  # noqa: E402
from redteam_ablation.metrics.wilson import wilson_interval  # noqa: E402

path = sys.argv[1] if len(sys.argv) > 1 else "runs/pilot-benign-haiku/benign.jsonl"
recs = [json.loads(line) for line in open(path, encoding="utf-8")]

arms_in_order = []
by = collections.defaultdict(list)
for r in recs:
    if r["variant"] not in arms_in_order:
        arms_in_order.append(r["variant"])
    by[r["variant"]].append(r)

print(f"=== {len(recs)} episodes from {path} ===\n")

print("-- per-arm: utility / denials / flags / latency / tool calls --")
for arm in arms_in_order:
    rs = by[arm]
    util = sum(bool(r["utility_success"]) for r in rs)
    denied = sum(bool(r["denied"]) for r in rs)
    flagged_eps = sum(bool(r["flagged_by"]) for r in rs)
    flag_names = collections.Counter(
        f for r in rs for f in r["flagged_by"]
    )
    walls = [r["wall_clock_seconds"] for r in rs]
    calls = [len(r["tool_call_trace"]) for r in rs]
    print(
        f"{arm:10s} n={len(rs):3d}  utility {util:2d}/{len(rs)}"
        f"  denied {denied}  flagged-eps {flagged_eps} {dict(flag_names) or ''}"
        f"  wall {statistics.mean(walls):5.1f}s±{statistics.stdev(walls):4.1f}"
        f"  calls/ep {statistics.mean(calls):4.1f} (tot {sum(calls)})"
    )

print("\n-- per-task utility concordance vs V0 (trial 0) --")
v0_util = {r["task_id"]: bool(r["utility_success"]) for r in by[arms_in_order[0]]}
v0_fails = sorted(t for t, ok in v0_util.items() if not ok)
print(f"V0 failed tasks ({len(v0_fails)}): {v0_fails}")
for arm in arms_in_order[1:]:
    arm_util = {r["task_id"]: bool(r["utility_success"]) for r in by[arm]}
    lost = sorted(t for t in v0_util if v0_util[t] and not arm_util.get(t, False))
    gained = sorted(t for t in v0_util if not v0_util[t] and arm_util.get(t, False))
    print(f"{arm:10s} lost-vs-V0 {len(lost)}: {lost}  gained-vs-V0 {len(gained)}: {gained}")

# Tasks that fail under k or more arms (capability floor candidates)
fail_count = collections.Counter()
for arm in arms_in_order:
    for r in by[arm]:
        if not r["utility_success"]:
            fail_count[r["task_id"]] += 1
print("\n-- tasks by number of arms in which they fail --")
for task, k in sorted(fail_count.items(), key=lambda kv: -kv[1]):
    print(f"  {task}: fails in {k}/{len(arms_in_order)} arms")

print("\n-- conditioned ALR cells (metrics.alr.alr_summary, baseline V0) --")
summary = alr_summary(recs)
for (arm, channel), cell in summary.items():
    print(
        f"{arm:10s} [{channel}] eligible {cell['n_eligible']:3d}"
        f"  denied {cell['denied']}  ALR {cell['alr']:.3f}"
        f"  Wilson [{cell['wilson_low']:.3f}, {cell['wilson_high']:.3f}]"
        f"  unconditioned {cell['n_unconditioned']}"
    )

strict_arms = [a for a in arms_in_order if a.endswith("-strict")]
strict_recs = [r for r in recs if r["variant"] in strict_arms]
eligible = [
    r for r in strict_recs
    if v0_util.get(r["task_id"], False)
]
den = sum(bool(r["denied"]) for r in eligible)
low, high, point = wilson_interval(den, len(eligible))
print(
    f"\n-- pooled strict arms ({', '.join(strict_arms)}) --\n"
    f"denied {den}/{len(eligible)} eligible episodes"
    f"  ALR {point:.4f}  Wilson 95% [{low:.4f}, {high:.4f}]"
)
