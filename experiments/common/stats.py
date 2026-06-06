"""Small statistical helpers for result aggregation."""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from statistics import mean, pstdev


SUMMARY_CSV_SCHEMA = [
    "schema_version",
    "run_id",
    "timestamp_utc",
    "git_commit",
    "runner",
    "metric",
    "group_key",
    "group_value",
    "trial_count",
    "success_count",
    "failure_count",
    "unsupported_count",
    "mean",
    "stddev",
    "min",
    "p50",
    "p95",
    "p99",
    "max",
    "unit",
    "source_csv",
]


def percentile(values: list[float], percent: float) -> float:
    if not values:
        raise ValueError("cannot compute percentile for empty values")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (percent / 100)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def summary(values: list[float]) -> dict[str, float]:
    if not values:
        raise ValueError("cannot summarize empty values")
    return {
        "mean": mean(values),
        "stddev": pstdev(values),
        "min": min(values),
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "max": max(values),
    }


def numeric_values(rows: list[dict[str, str]], column: str) -> list[float]:
    values: list[float] = []
    for row in rows:
        value = row.get(column, "")
        if value == "":
            continue
        values.append(float(value))
    return values


def boolean_count(rows: list[dict[str, str]], column: str, expected: bool) -> int:
    wanted = "True" if expected else "False"
    return sum(1 for row in rows if row.get(column) == wanted)


def result_count(rows: list[dict[str, str]], result: str) -> int:
    return sum(1 for row in rows if row.get("result") == result)


def grouped_rows(rows: list[dict[str, str]], columns: list[str]) -> dict[tuple[str, ...], list[dict[str, str]]]:
    groups: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row.get(column, "") for column in columns)].append(row)
    return groups


def stats_or_empty(values: list[float]) -> dict[str, float | str]:
    if not values:
        return {
            "mean": "",
            "stddev": "",
            "min": "",
            "p50": "",
            "p95": "",
            "p99": "",
            "max": "",
        }
    return summary(values)


PERFORMANCE_LATENCY_SUMMARY_SCHEMA = [
    "operation",
    "lineage_depth",
    "batch_size",
    "cache_mode",
    "timed_section",
    "trial_count",
    "mean",
    "stddev",
    "min",
    "p50",
    "p95",
    "p99",
    "max",
    "unit",
]


def latency_summary_from_raw(raw_csv: str | Path) -> list[dict[str, object]]:
    """Build performance latency summary rows from raw CSV rows only."""

    groups: dict[tuple[str, str, str, str, str], list[float]] = defaultdict(list)
    with Path(raw_csv).open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["warmup"] != "False" or row["ok"] != "True":
                continue
            key = (
                row["operation"],
                row["lineage_depth"],
                row["batch_size"],
                row["cache_mode"],
                row["timed_section"],
            )
            groups[key].append(float(row["duration_ms"]))

    rows: list[dict[str, object]] = []
    for key in sorted(groups):
        operation, lineage_depth, batch_size, cache_mode, timed_section = key
        values = groups[key]
        stats = summary(values)
        rows.append({
            "operation": operation,
            "lineage_depth": lineage_depth,
            "batch_size": batch_size,
            "cache_mode": cache_mode,
            "timed_section": timed_section,
            "trial_count": len(values),
            "mean": stats["mean"],
            "stddev": stats["stddev"],
            "min": stats["min"],
            "p50": stats["p50"],
            "p95": stats["p95"],
            "p99": stats["p99"],
            "max": stats["max"],
            "unit": "ms",
        })
    return rows
