from __future__ import annotations

import math
from collections import defaultdict
from statistics import median
from typing import Any, Iterable

from security.containment_layer.evaluation.conditions import Condition


def percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * quantile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    weight = index - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def latency_summary(values: list[float]) -> dict[str, float]:
    return {
        "median_latency_ms": median(values) if values else 0.0,
        "latency_q1_ms": percentile(values, 0.25),
        "latency_q3_ms": percentile(values, 0.75),
        "latency_ci95_low_ms": percentile(values, 0.025),
        "latency_ci95_high_ms": percentile(values, 0.975),
    }


def factor_effects(
    by_condition: dict[str, dict[str, Any]],
    conditions: Iterable[Condition],
) -> dict[str, list[dict[str, Any]]]:
    runtime_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    architecture_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for condition in conditions:
        row = by_condition[condition.id]
        runtime_groups[condition.factor_runtime].append(row)
        architecture_groups[condition.architecture].append(row)
    return {
        "by_runtime": [_factor_row("runtime", key, rows) for key, rows in sorted(runtime_groups.items())],
        "by_architecture": [_factor_row("architecture", key, rows) for key, rows in sorted(architecture_groups.items())],
    }


def pareto_rows(
    by_condition: dict[str, dict[str, Any]],
    conditions: Iterable[Condition],
) -> list[dict[str, Any]]:
    return [
        {
            "condition": condition.id,
            "factor_runtime": condition.factor_runtime,
            "factor_architecture": condition.architecture,
            "median_latency_ms": by_condition[condition.id]["median_latency_ms"],
            "containment_rate": by_condition[condition.id]["containment_rate"],
            "fallout_radius": by_condition[condition.id]["fallout_radius"],
            "closed_categories": 6 - by_condition[condition.id]["fallout_radius"],
        }
        for condition in conditions
    ]


def _factor_row(factor: str, level: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "factor": factor,
        "level": level,
        "conditions": len(rows),
        "mean_containment_rate": sum(row["containment_rate"] for row in rows) / len(rows),
        "mean_fallout_radius": sum(row["fallout_radius"] for row in rows) / len(rows),
        "mean_false_positive_rate": sum(row["false_positive_rate"] for row in rows) / len(rows),
        "mean_boundary_denied_rate": sum(row["boundary_probe_denied_rate"] for row in rows) / len(rows),
    }

