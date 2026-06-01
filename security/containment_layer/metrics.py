from __future__ import annotations

from collections import defaultdict
from statistics import mean
from typing import Iterable

from security.containment_layer.compromised_runner import AttackTrialResult


def results_by_condition(results: Iterable[AttackTrialResult]) -> list[dict]:
    return [_aggregate_group(condition, rows) for condition, rows in _group(results, lambda r: r.condition).items()]


def results_by_family(results: Iterable[AttackTrialResult]) -> list[dict]:
    out = []
    for (condition, family), rows in _group(results, lambda r: (r.condition, r.family)).items():
        row = _aggregate_basic(rows)
        row.update({"condition": condition, "family": family})
        out.append(row)
    return sorted(out, key=lambda r: (r["condition"], r["family"]))


def results_by_asset(results: Iterable[AttackTrialResult]) -> list[dict]:
    out = []
    for (condition, asset), rows in _group(results, lambda r: (r.condition, r.target_asset)).items():
        row = _aggregate_basic(rows)
        row.update({"condition": condition, "target_asset": asset})
        out.append(row)
    return sorted(out, key=lambda r: (r["condition"], r["target_asset"]))


def summary(results: Iterable[AttackTrialResult], metadata: dict | None = None) -> dict:
    rows = list(results)
    return {
        "metadata": metadata or {},
        "trial_count": len(rows),
        "results_by_condition": results_by_condition(rows),
        "results_by_family": results_by_family(rows),
        "results_by_asset": results_by_asset(rows),
    }


def _aggregate_group(condition: str, rows: list[AttackTrialResult]) -> dict:
    row = _aggregate_basic(rows)
    row.update(
        {
            "condition": condition,
            "secret_read_success_rate": _rate(rows, lambda r: r.canary_observed),
            "state_mutation_success_rate": _rate(rows, lambda r: r.protected_file_modified or r.protected_file_deleted),
            "log_tamper_success_rate": _rate([r for r in rows if r.family == "A7_log_tampering"], lambda r: r.success),
            "network_egress_success_rate": _rate([r for r in rows if r.family == "A9_network_egress"], lambda r: r.unauthorized_network_received),
            "proxy_abuse_success_rate": _rate([r for r in rows if r.family == "A6_proxy_abuse"], lambda r: r.proxy_abuse_success),
            "seedbox_bypass_success_rate": _rate([r for r in rows if r.family == "A11_seedbox_acl_bypass"], lambda r: r.success),
            "resource_integrity_preservation_rate": _rate(rows, lambda r: r.resource_integrity_preserved),
        }
    )
    return row


def _aggregate_basic(rows: list[AttackTrialResult]) -> dict:
    return {
        "trials": len(rows),
        "successful_unauthorized_accesses": sum(1 for row in rows if row.success),
        "fallout_success_rate": _rate(rows, lambda r: r.success),
        "mean_fallout_score": mean([row.fallout_score for row in rows]) if rows else 0.0,
    }


def _rate(rows: list[AttackTrialResult], predicate) -> float:
    if not rows:
        return 0.0
    return sum(1 for row in rows if predicate(row)) / len(rows)


def _group(rows: Iterable[AttackTrialResult], key_func) -> dict:
    grouped = defaultdict(list)
    for row in rows:
        grouped[key_func(row)].append(row)
    return dict(grouped)

