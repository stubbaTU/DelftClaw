from __future__ import annotations

import argparse
import csv
import random
from itertools import combinations
from pathlib import Path
from typing import Any

from security.accountability_layer.evaluation.analysis_utils import write_rows


FALLOUT_METRICS = [
    "fallout_broadcasts",
    "fraudulent_microtasks_accepted",
    "wash_trades_accepted",
    "collusive_endorsements_accepted",
    "fraudulent_reputation_gain",
]


def analyze(trials_csv: Path, out_dir: Path, *, bootstrap_samples: int = 2000) -> None:
    try:
        from lifelines import KaplanMeierFitter
        from lifelines.statistics import logrank_test
        from scipy.stats import mannwhitneyu
    except ImportError as exc:
        raise RuntimeError("SQ2 statistics require `pip install lifelines scipy`") from exc

    with trials_csv.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    rows = [row for row in rows if not row.get("error")]
    conditions = sorted({row["condition"] for row in rows})

    survival_rows: list[dict[str, Any]] = []
    for condition in conditions:
        group = [row for row in rows if row["condition"] == condition]
        durations = [float(row["reputation_lag_events"]) for row in group]
        observed = [_bool(row["expelled"]) for row in group]
        km = KaplanMeierFitter().fit(durations, event_observed=observed, label=condition)
        ci = km.confidence_interval_survival_function_
        for time, survival in km.survival_function_[condition].items():
            survival_rows.append({
                "condition": condition,
                "time": time,
                "survival_probability": survival,
                "ci_lower": ci.loc[time].iloc[0],
                "ci_upper": ci.loc[time].iloc[1],
                "median_time_to_expulsion": km.median_survival_time_,
            })
    write_rows(out_dir / "sq2_survival.csv", survival_rows)

    significance: list[dict[str, Any]] = []
    pvalue_rows: list[dict[str, Any]] = []
    for left, right in combinations(conditions, 2):
        a = [row for row in rows if row["condition"] == left]
        b = [row for row in rows if row["condition"] == right]
        result = logrank_test(
            [float(row["reputation_lag_events"]) for row in a],
            [float(row["reputation_lag_events"]) for row in b],
            event_observed_A=[_bool(row["expelled"]) for row in a],
            event_observed_B=[_bool(row["expelled"]) for row in b],
        )
        pvalue_rows.append({
            "test": "logrank",
            "metric": "time_to_expulsion",
            "condition_a": left,
            "condition_b": right,
            "p_value": float(result.p_value),
            "effect_size": "",
            "ci_lower": "",
            "ci_upper": "",
        })
        for metric in FALLOUT_METRICS:
            av = [float(row[metric]) for row in a]
            bv = [float(row[metric]) for row in b]
            test = mannwhitneyu(av, bv, alternative="two-sided")
            low, high = _bootstrap_mean_difference_ci(av, bv, bootstrap_samples)
            pvalue_rows.append({
                "test": "mann_whitney_u",
                "metric": metric,
                "condition_a": left,
                "condition_b": right,
                "p_value": float(test.pvalue),
                "effect_size": _cliffs_delta(av, bv),
                "ci_lower": low,
                "ci_upper": high,
            })
    adjusted = _holm_adjust([float(row["p_value"]) for row in pvalue_rows])
    for row, p_adjusted in zip(pvalue_rows, adjusted):
        row["p_value_holm"] = p_adjusted
        significance.append(row)
    write_rows(out_dir / "sq2_significance.csv", significance)


def _bootstrap_mean_difference_ci(a: list[float], b: list[float], samples: int) -> tuple[float, float]:
    rng = random.Random(20260609)
    diffs = []
    for _ in range(samples):
        ar = [rng.choice(a) for _ in a]
        br = [rng.choice(b) for _ in b]
        diffs.append(sum(ar) / len(ar) - sum(br) / len(br))
    diffs.sort()
    return diffs[int(samples * 0.025)], diffs[min(samples - 1, int(samples * 0.975))]


def _cliffs_delta(a: list[float], b: list[float]) -> float:
    greater = sum(x > y for x in a for y in b)
    lower = sum(x < y for x in a for y in b)
    return (greater - lower) / (len(a) * len(b))


def _holm_adjust(pvalues: list[float]) -> list[float]:
    ordered = sorted(enumerate(pvalues), key=lambda item: item[1])
    adjusted = [0.0] * len(pvalues)
    running = 0.0
    total = len(pvalues)
    for rank, (index, pvalue) in enumerate(ordered):
        running = max(running, min(1.0, (total - rank) * pvalue))
        adjusted[index] = running
    return adjusted


def _bool(value: str) -> bool:
    return value.lower() in {"true", "1", "yes"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run survival and fallout significance analysis for SQ2.")
    parser.add_argument("--trials", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--bootstrap-samples", type=int, default=2000)
    args = parser.parse_args()
    analyze(args.trials, args.out, bootstrap_samples=args.bootstrap_samples)
    print(f"wrote SQ2 statistical outputs to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
