from __future__ import annotations

import argparse
import json
from pathlib import Path

from security.accountability_layer.analysis_utils import (
    aggregate_rescores,
    discover_c1_logs,
    read_log_entries,
    rescore_entries,
    write_rows,
)
from security.accountability_layer.live_scenario_schema import CONDITION_B1, CONDITION_B2, CONDITION_C1


def rescore_run(run_dir: Path, out_dir: Path, conditions: list[str], threshold: int) -> list[dict]:
    rows: list[dict] = []
    for scenario, log_path in discover_c1_logs(run_dir):
        entries = read_log_entries(log_path)
        for condition in conditions:
            rows.append(rescore_entries(entries, scenario, condition=condition, threshold=threshold))
    write_rows(out_dir / "sq2_rescored_trials.csv", rows)
    write_rows(out_dir / "sq2_ablation_by_condition.csv", aggregate_rescores(rows))
    (out_dir / "sq2_rescored_trials.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Post-hoc SQ2 ablation re-scoring over recorded C1 logs.")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--conditions", nargs="+", default=[CONDITION_B1, CONDITION_B2, CONDITION_C1])
    parser.add_argument("--threshold", type=int, default=5)
    args = parser.parse_args()
    rows = rescore_run(args.run_dir, args.out, args.conditions, args.threshold)
    print(f"rescored {len(rows)} condition-scenario cells")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
