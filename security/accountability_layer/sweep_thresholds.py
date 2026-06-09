from __future__ import annotations

import argparse
from pathlib import Path

from security.accountability_layer.analysis_utils import (
    aggregate_rescores,
    discover_c1_logs,
    rescore_entries,
    scenario_replay_entries,
    write_rows,
)
from security.accountability_layer.live_scenario_schema import CONDITION_B2, CONDITION_C1


def sweep(
    run_dir: Path,
    out_dir: Path,
    thresholds: list[int],
    conditions: list[str],
    *,
    max_false_positive_rate: float = 0.05,
) -> list[dict]:
    rows: list[dict] = []
    for scenario, _log_path in discover_c1_logs(run_dir):
        entries = scenario_replay_entries(scenario)
        for threshold in thresholds:
            for condition in conditions:
                rows.append(rescore_entries(entries, scenario, condition=condition, threshold=threshold))
    aggregates = aggregate_rescores(rows)
    write_rows(out_dir / "sq2_threshold_sweep_trials.csv", rows)
    write_rows(out_dir / "sq2_threshold_sweep.csv", aggregates)
    write_rows(out_dir / "sq2_adaptive_degradation.csv", aggregates)
    write_rows(out_dir / "sq2_false_positives.csv", [row for row in rows if row["false_positive_count"]])
    write_rows(out_dir / "sq2_roc_frontier.csv", aggregates)
    write_rows(out_dir / "sq2_latency_fp_frontier.csv", _pareto_frontier(aggregates))
    write_rows(out_dir / "sq2_operating_points.csv", _select_operating_points(aggregates, max_false_positive_rate))
    return aggregates


def _select_operating_points(rows: list[dict], max_false_positive_rate: float) -> list[dict]:
    selected: list[dict] = []
    keys = sorted({(row["condition"], row["attacker_strategy"]) for row in rows})
    for condition, strategy in keys:
        candidates = [
            row for row in rows
            if row["condition"] == condition
            and row["attacker_strategy"] == strategy
            and row["false_positive_rate"] <= max_false_positive_rate
        ]
        if not candidates:
            continue
        choice = min(candidates, key=lambda row: (row["threshold"], -row["detection_rate"]))
        selected.append({
            **choice,
            "selection_rule": f"lowest threshold with false_positive_rate <= {max_false_positive_rate}",
        })
    return selected


def _pareto_frontier(rows: list[dict]) -> list[dict]:
    frontier: list[dict] = []
    keys = sorted({(row["condition"], row["attacker_strategy"]) for row in rows})
    for condition, strategy in keys:
        group = [
            row for row in rows
            if row["condition"] == condition and row["attacker_strategy"] == strategy
        ]
        for candidate in group:
            dominated = any(
                other is not candidate
                and other["false_positive_rate"] <= candidate["false_positive_rate"]
                and other["detection_rate"] >= candidate["detection_rate"]
                and (
                    other["false_positive_rate"] < candidate["false_positive_rate"]
                    or other["detection_rate"] > candidate["detection_rate"]
                )
                for other in group
            )
            if not dominated:
                frontier.append(candidate)
    return frontier


def main() -> int:
    parser = argparse.ArgumentParser(description="Sweep SQ2 estimator thresholds without invoking a model.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--thresholds", nargs="+", type=int, default=list(range(1, 11)))
    parser.add_argument("--conditions", nargs="+", default=[CONDITION_B2, CONDITION_C1])
    parser.add_argument("--max-false-positive-rate", type=float, default=0.05)
    args = parser.parse_args()
    rows = sweep(
        args.run_dir,
        args.out,
        args.thresholds,
        args.conditions,
        max_false_positive_rate=args.max_false_positive_rate,
    )
    print(f"wrote {len(rows)} threshold aggregate cells")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
