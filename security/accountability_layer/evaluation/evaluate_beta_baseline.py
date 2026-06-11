from __future__ import annotations

import argparse
from pathlib import Path

from security.accountability_layer.evaluation.analysis_utils import discover_c1_logs, read_log_entries, write_rows
from security.accountability_layer.infrastructure.beta_reputation import BetaReputationEstimator


def evaluate(run_dir: Path, out_dir: Path, cutoffs: list[float]) -> list[dict]:
    trials: list[dict] = []
    for scenario, log_path in discover_c1_logs(run_dir):
        events = []
        for entry in read_log_entries(log_path):
            event = (entry.get("details") or {}).get("event")
            if isinstance(event, dict):
                events.append(event)
        for cutoff in cutoffs:
            estimator = BetaReputationEstimator(trust_cutoff=cutoff)
            for event in events:
                estimator.process(event)
            expelled = scenario.primary_attacker in estimator.expelled_agents
            false_positives = estimator.expelled_agents.intersection(scenario.honest_agents)
            trials.append({
                "condition": "B3_beta_reputation",
                "scenario_id": scenario.scenario_id,
                "family": scenario.family,
                "attacker_strategy": scenario.attacker_strategy,
                "seed": scenario.seed,
                "split": "heldout" if scenario.seed == 5 else "tuning",
                "trust_cutoff": cutoff,
                "expelled": expelled,
                "false_positive_count": len(false_positives),
                "false_positive_rate": len(false_positives) / len(scenario.honest_agents),
                "honest_agent_count": len(scenario.honest_agents),
            })
    write_rows(out_dir / "sq2_beta_trials.csv", trials)
    aggregates = []
    for cutoff in cutoffs:
        for split in ("tuning", "heldout"):
            group = [row for row in trials if row["trust_cutoff"] == cutoff and row["split"] == split]
            if not group:
                continue
            aggregates.append({
                "condition": "B3_beta_reputation",
                "split": split,
                "trust_cutoff": cutoff,
                "trials": len(group),
                "detection_rate": sum(row["expelled"] for row in group) / len(group),
                "false_positive_rate": sum(row["false_positive_count"] for row in group)
                / sum(row["honest_agent_count"] for row in group),
            })
    write_rows(out_dir / "sq2_beta_by_cutoff.csv", aggregates)
    return aggregates


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate a post-hoc Beta-reputation SQ2 baseline.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cutoffs", nargs="+", type=float, default=[0.2, 0.3, 0.35, 0.4, 0.5])
    args = parser.parse_args()
    rows = evaluate(args.run_dir, args.out, args.cutoffs)
    print(f"wrote {len(rows)} Beta-reputation aggregate cells")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
