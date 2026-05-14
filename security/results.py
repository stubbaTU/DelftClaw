import csv
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable

from security.contracts import AccountabilityMetrics, ExecutionResult, LogIntegrityExperimentResult


def write_json(path: str | Path, data: Any):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        json.dump(_to_jsonable(data), f, indent=2, sort_keys=True)


def write_csv(path: str | Path, rows: Iterable[dict[str, Any]]):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    if not rows:
        with open(target, "w", encoding="utf-8", newline="") as f:
            f.write("")
        return

    fieldnames = sorted({key for row in rows for key in row.keys()})
    with open(target, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def execution_rows(label: str, results: list[ExecutionResult]) -> list[dict[str, Any]]:
    return [
        {
            "condition": label,
            "index": index,
            "payload_id": result.payload_id,
            "sender_id": result.sender_id,
            "requested_tool": result.requested_tool,
            "executed": result.executed,
            "authorized": result.authorized,
            "attack_success": result.attack_success,
            "reason": result.reason,
        }
        for index, result in enumerate(results, start=1)
    ]


def accountability_row(label: str, metrics: AccountabilityMetrics) -> dict[str, Any]:
    return {
        "condition": label,
        "subject_id": metrics.subject_id,
        "accountability_enabled": metrics.accountability_enabled,
        "attempted_actions": metrics.attempted_actions,
        "unauthorized_executions": metrics.unauthorized_executions,
        "fake_donations": metrics.fake_donations,
        "honest_transactions_stolen": metrics.honest_transactions_stolen,
        "wash_trades_detected": metrics.wash_trades_detected,
        "atomic_microtasks_claimed": metrics.atomic_microtasks_claimed,
        "fallout_radius": metrics.fallout_radius,
        "blast_radius": metrics.blast_radius,
        "first_malicious_step": metrics.first_malicious_step,
        "detection_step": metrics.detection_step,
        "reputation_lag": metrics.reputation_lag,
        "accepted_harmful_actions_during_lag": metrics.accepted_harmful_actions_during_lag,
        "blocked_actions": metrics.blocked_actions,
        "final_score": metrics.final_score,
        "expelled": metrics.expelled,
        "expulsion_step": metrics.expulsion_step,
        "integrity_ok": metrics.integrity_ok,
    }


def integrity_rows(result: LogIntegrityExperimentResult) -> list[dict[str, Any]]:
    return [
        {
            "mode": result.mode,
            "passed": result.passed,
            "host_log_path_exposed": result.host_log_path_exposed,
            "attack_name": attempt.attack_name,
            "attempted": attempt.attempted,
            "succeeded": attempt.succeeded,
            "host_log_changed": attempt.host_log_changed,
            "host_log_deleted": attempt.host_log_deleted,
            "integrity_ok": attempt.integrity_ok,
            "error": attempt.error,
        }
        for attempt in result.attempts
    ]


def _to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _to_jsonable(asdict(value))
    if isinstance(value, dict):
        return {key: _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(item) for item in value]
    return value
