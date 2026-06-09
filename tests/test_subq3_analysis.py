from __future__ import annotations

from security.containment_layer.analysis import factor_effects, latency_summary, pareto_rows
from security.containment_layer.conditions import resolve_conditions


def test_latency_factor_effects_and_pareto_rows() -> None:
    conditions = resolve_conditions(["C0_uncontained", "A1_arch_only_runc"])
    by_condition = {
        "C0_uncontained": _row(0.1, 6, 0.0, 0.0, 10.0),
        "A1_arch_only_runc": _row(0.9, 1, 0.0, 0.5, 20.0),
    }

    latency = latency_summary([1.0, 2.0, 3.0, 4.0])
    assert latency["median_latency_ms"] == 2.5
    assert latency["latency_q1_ms"] < latency["latency_q3_ms"]

    effects = factor_effects(by_condition, conditions)
    arch = {row["level"]: row for row in effects["by_architecture"]}
    assert arch["on"]["mean_containment_rate"] == 0.9
    assert arch["off"]["mean_containment_rate"] == 0.1

    pareto = pareto_rows(by_condition, conditions)
    assert pareto[1]["closed_categories"] == 5


def _row(containment: float, fallout: int, fp: float, boundary: float, latency: float) -> dict:
    return {
        "containment_rate": containment,
        "fallout_radius": fallout,
        "false_positive_rate": fp,
        "boundary_probe_denied_rate": boundary,
        "median_latency_ms": latency,
    }
