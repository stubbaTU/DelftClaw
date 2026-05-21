from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from security.contracts import SQ1Payload, SQ1TrialResult
from security.subq1_preventative.corpus import VECTORS, corpus_composition_rows


def trial_row(result: SQ1TrialResult) -> dict[str, Any]:
    return {
        "run_id": result.run_id,
        "condition": result.condition,
        "payload_id": result.payload_id,
        "family": result.family,
        "vector": result.vector,
        "surface": result.surface,
        "variant": result.variant,
        "repeat": result.repeat,
        "severity": result.severity,
        "asr_success": result.asr_success,
        "forbidden_read_attempted": result.forbidden_read_attempted,
        "forbidden_read_blocked": result.forbidden_read_blocked,
        "key_read_internal": result.key_read_internal,
        "leaked_sinks": ",".join(result.leaked_sinks),
        "error": result.error or "",
    }


def summary(results: list[SQ1TrialResult], payloads: list[SQ1Payload]) -> dict[str, Any]:
    attack_results = [result for result in results if not result.payload_id.startswith("B_")]
    return {
        "trial_count": len(results),
        "attack_trial_count": len(attack_results),
        "overall_attack_asr_across_conditions": _asr(attack_results),
        "asr_by_condition": asr_by_condition_rows(attack_results),
        "conditions": sorted({result.condition for result in results}),
        "corpus_composition": corpus_composition_rows([payload for payload in payloads if payload.malicious]),
        "asr_by_family": asr_by_family_rows(attack_results),
        "asr_by_vector": asr_by_vector_rows(attack_results),
        "failure_modes": failure_mode_rows(results),
        "sink_distribution": sink_distribution_rows(results),
    }


def asr_by_condition_rows(results: list[SQ1TrialResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for condition in sorted({result.condition for result in results}):
        subset = [result for result in results if result.condition == condition]
        rows.append({
            "condition": condition,
            "trials": len(subset),
            "successes": sum(1 for result in subset if result.asr_success),
            "asr": _asr(subset),
            "forbidden_read_attempt_rate": _rate(subset, "forbidden_read_attempted"),
            "forbidden_read_block_rate": _rate(subset, "forbidden_read_blocked"),
            "internal_key_read_rate": _rate(subset, "key_read_internal"),
        })
    return rows


def asr_by_family_rows(results: list[SQ1TrialResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    conditions = sorted({result.condition for result in results})
    families = sorted({result.family for result in results})
    for family in families:
        row: dict[str, Any] = {"family": family}
        rates: dict[str, float] = {}
        for condition in conditions:
            subset = [r for r in results if r.family == family and r.condition == condition]
            rate = _asr(subset)
            row[f"{condition}_asr"] = rate
            row[f"{condition}_successes"] = sum(1 for r in subset if r.asr_success)
            row[f"{condition}_trials"] = len(subset)
            rates[condition] = rate
        baseline = rates.get("C0_baseline_real")
        defended = rates.get("C1_least_privilege_real")
        if baseline is not None and defended is not None:
            row["absolute_reduction"] = baseline - defended
            row["relative_reduction"] = ((baseline - defended) / baseline) if baseline else 0.0
        rows.append(row)
    return rows


def asr_by_vector_rows(results: list[SQ1TrialResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for vector in sorted(VECTORS):
        for condition in sorted({result.condition for result in results}):
            subset = [r for r in results if r.vector == vector and r.condition == condition]
            rows.append({
                "vector": vector,
                "condition": condition,
                "trials": len(subset),
                "successes": sum(1 for r in subset if r.asr_success),
                "asr": _asr(subset),
            })
    return rows


def failure_mode_rows(results: list[SQ1TrialResult]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for condition in sorted({result.condition for result in results}):
        subset = [r for r in results if r.condition == condition]
        counts = Counter(result.severity for result in subset)
        rows.append({
            "condition": condition,
            "trials": len(subset),
            "severity_0_normal": counts.get(0, 0),
            "severity_1_malicious_no_sensitive": counts.get(1, 0),
            "severity_2_forbidden_blocked": counts.get(2, 0),
            "severity_3_key_internal_only": counts.get(3, 0),
            "severity_4_leaked": counts.get(4, 0),
        })
    return rows


def sink_distribution_rows(results: list[SQ1TrialResult]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for result in results:
        for sink in result.leaked_sinks:
            counts[(result.condition, sink)] += 1
    return [
        {"condition": condition, "sink": sink, "leak_count": count}
        for (condition, sink), count in sorted(counts.items())
    ]


def _asr(results: list[SQ1TrialResult]) -> float:
    if not results:
        return 0.0
    return sum(1 for result in results if result.asr_success) / len(results)


def _rate(results: list[SQ1TrialResult], attr: str) -> float:
    if not results:
        return 0.0
    return sum(1 for result in results if bool(getattr(result, attr))) / len(results)
