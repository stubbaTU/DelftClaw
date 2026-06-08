from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


TRIAL_COLUMNS = [
    "condition",
    "suite",
    "attack",
    "model",
    "user_task_id",
    "injection_task_id",
    "utility_success",
    "attack_success",
    "error",
    "num_tool_calls",
    "num_allowed_tool_calls",
    "num_blocked_tool_calls",
    "blocked_reasons",
    "final_output_blocked",
]


METRIC_COLUMNS = [
    "condition",
    "suite",
    "attack",
    "model",
    "num_trials",
    "utility_success_rate",
    "attack_success_rate",
    "blocked_tool_call_rate",
    "mean_blocked_tool_calls",
    "false_deny_count",
    "false_deny_rate",
    "error_count",
]


def suite_results_to_trial_rows(
    *,
    condition: str,
    suite: str,
    attack: str,
    model: str,
    suite_results: Any,
    permission_entries: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    utility = _suite_result_field(suite_results, "utility_results")
    security = _suite_result_field(suite_results, "security_results")
    entries = permission_entries or []
    rows: list[dict[str, Any]] = []
    for key, utility_success in utility.items():
        user_task_id, injection_task_id = _split_key(key)
        relevant = _entries_for(entries, user_task_id, injection_task_id)
        tool_decisions = [entry for entry in relevant if entry.get("event_type") != "capability_grant"]
        blocked = [entry for entry in relevant if entry.get("decision") == "deny"]
        allowed = [entry for entry in relevant if entry.get("decision") in {"allow", "allow_via_proxy"}]
        rows.append({
            "condition": condition,
            "suite": suite,
            "attack": attack,
            "model": model,
            "user_task_id": user_task_id,
            "injection_task_id": injection_task_id,
            "utility_success": bool(utility_success),
            "attack_success": bool(security.get(key, False)),
            "error": "",
            "num_tool_calls": len(tool_decisions),
            "num_allowed_tool_calls": len(allowed),
            "num_blocked_tool_calls": len(blocked),
            "blocked_reasons": "; ".join(str(entry.get("reason", "")) for entry in blocked),
            "final_output_blocked": any("final output blocked" in str(entry.get("reason", "")) for entry in blocked),
        })
    return rows


def _suite_result_field(suite_results: Any, field: str) -> dict[Any, Any]:
    if isinstance(suite_results, dict):
        value = suite_results.get(field, {})
    else:
        value = getattr(suite_results, field, {})
    return value or {}


def write_outputs(
    output_dir: str | Path,
    *,
    metadata: dict[str, Any],
    trial_rows: list[dict[str, Any]],
    permission_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    metrics = metrics_by_condition(trial_rows)
    summary = {"metadata": metadata, "metrics_by_condition": metrics}
    _write_json(target / "agentdojo_vukzero_run_metadata.json", metadata)
    _write_json(target / "agentdojo_vukzero_summary.json", summary)
    _write_csv(target / "agentdojo_vukzero_trials.csv", TRIAL_COLUMNS, trial_rows)
    _write_jsonl(target / "agentdojo_vukzero_trials.jsonl", trial_rows)
    _write_csv(target / "agentdojo_vukzero_metrics_by_condition.csv", METRIC_COLUMNS, metrics)
    _write_jsonl(target / "agentdojo_vukzero_permission_decisions.jsonl", permission_entries)
    blocked = [entry for entry in permission_entries if entry.get("decision") == "deny"]
    _write_csv(target / "agentdojo_vukzero_blocked_calls.csv", sorted({key for row in blocked for key in row}) or ["decision"], blocked)
    false_denies = [row for row in trial_rows if row["condition"].endswith("vukzero") and row["num_blocked_tool_calls"] and row["injection_task_id"] == "" and not row["utility_success"]]
    _write_csv(target / "agentdojo_vukzero_false_denies.csv", TRIAL_COLUMNS, false_denies)
    (target / "run.log").write_text("AgentDojo-VukZero adapter run completed.\n", encoding="utf-8")
    return summary


def metrics_by_condition(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for condition in sorted({row["condition"] for row in rows}):
        subset = [row for row in rows if row["condition"] == condition]
        if not subset:
            continue
        blocked_total = sum(int(row["num_blocked_tool_calls"]) for row in subset)
        tool_total = sum(int(row["num_tool_calls"]) for row in subset)
        false_denies = [
            row for row in subset
            if row["num_blocked_tool_calls"] and row["injection_task_id"] == "" and not row["utility_success"]
        ]
        out.append({
            "condition": condition,
            "suite": subset[0]["suite"],
            "attack": subset[0]["attack"],
            "model": subset[0]["model"],
            "num_trials": len(subset),
            "utility_success_rate": _rate(sum(bool(row["utility_success"]) for row in subset), len(subset)),
            "attack_success_rate": _rate(sum(bool(row["attack_success"]) for row in subset), len(subset)),
            "blocked_tool_call_rate": _rate(blocked_total, tool_total),
            "mean_blocked_tool_calls": blocked_total / len(subset),
            "false_deny_count": len(false_denies),
            "false_deny_rate": _rate(len(false_denies), len(subset)),
            "error_count": sum(1 for row in subset if row["error"]),
        })
    return out


def _entries_for(entries: list[dict[str, Any]], user_task_id: str, injection_task_id: str) -> list[dict[str, Any]]:
    return [
        entry for entry in entries
        if entry.get("user_task_id") in {None, "", user_task_id}
        and entry.get("injection_task_id") in {None, "", injection_task_id}
    ]


def _split_key(key: Any) -> tuple[str, str]:
    if isinstance(key, tuple):
        if len(key) == 1:
            return str(key[0]), ""
        return str(key[0]), str(key[1])
    return str(key), ""


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
