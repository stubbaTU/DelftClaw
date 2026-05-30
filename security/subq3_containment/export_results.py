from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from security.subq3_containment.compromised_runner import AttackTrialResult
from security.subq3_containment.metrics import results_by_asset, results_by_condition, results_by_family, summary


TRIAL_COLUMNS = [
    "attack_id",
    "family",
    "variant",
    "target_asset",
    "condition",
    "profile_name",
    "uses_gvisor",
    "uses_docker",
    "uses_iptables",
    "attack_type",
    "success",
    "blocked",
    "fallout_score",
    "canary_observed",
    "canary_exfiltrated",
    "protected_file_modified",
    "protected_file_deleted",
    "log_chain_valid_after",
    "unauthorized_network_received",
    "proxy_abuse_success",
    "resource_integrity_preserved",
    "exit_code",
    "timeout",
    "error",
    "block_reason",
]


def export_sq3_results(results: list[AttackTrialResult], out_dir: str | Path, metadata: dict[str, Any]) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    metadata_path = out / "sq3_run_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    _write_csv(out / "sq3_trials.csv", TRIAL_COLUMNS, [row.to_trial_row() for row in results])
    with (out / "sq3_trials.jsonl").open("w", encoding="utf-8") as handle:
        for row in results:
            handle.write(json.dumps(asdict(row), sort_keys=True, default=str) + "\n")

    by_condition = results_by_condition(results)
    by_family = results_by_family(results)
    by_asset = results_by_asset(results)
    _write_csv(out / "sq3_results_by_condition.csv", _condition_columns(), by_condition)
    _write_csv(out / "sq3_results_by_family.csv", ["condition", "family", "trials", "successful_unauthorized_accesses", "fallout_success_rate", "mean_fallout_score"], by_family)
    _write_csv(out / "sq3_results_by_asset.csv", ["condition", "target_asset", "trials", "successful_unauthorized_accesses", "fallout_success_rate", "mean_fallout_score"], by_asset)
    _write_csv(out / "sq3_proxy_results.csv", TRIAL_COLUMNS, [r.to_trial_row() for r in results if r.attack_type == "proxy_call"])
    _write_csv(out / "sq3_network_results.csv", _network_columns(), [_network_row(r) for r in results if r.family == "A9_network_egress" or r.attack_type == "network_send"])
    _write_csv(out / "sq3_log_integrity.csv", _log_columns(), [_log_row(r) for r in results if r.target_asset == "accountability_log" or r.family == "A7_log_tampering"])
    _write_csv(out / "sq3_resource_integrity.csv", _resource_columns(), [_resource_row(r) for r in results])

    run_summary = summary(results, metadata=metadata)
    (out / "sq3_summary.json").write_text(json.dumps(run_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "run.log").write_text(
        f"SQ3 containment run completed with {len(results)} trials.\n",
        encoding="utf-8",
    )
    return run_summary


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _condition_columns() -> list[str]:
    return [
        "condition",
        "trials",
        "successful_unauthorized_accesses",
        "fallout_success_rate",
        "mean_fallout_score",
        "secret_read_success_rate",
        "state_mutation_success_rate",
        "log_tamper_success_rate",
        "network_egress_success_rate",
        "proxy_abuse_success_rate",
        "seedbox_bypass_success_rate",
        "resource_integrity_preservation_rate",
    ]


def _log_columns() -> list[str]:
    return [
        "condition",
        "attack_id",
        "log_exists",
        "log_chain_valid_before",
        "log_chain_valid_after",
        "tampering_attempted",
        "tampering_detected",
        "silent_log_corruption",
    ]


def _network_columns() -> list[str]:
    return [
        "condition",
        "attack_id",
        "attempted_destination",
        "allowed_peer_received",
        "unauthorized_exfil_received",
        "canary_received_by_unauthorized_sink",
        "network_blocked",
    ]


def _resource_columns() -> list[str]:
    return [
        "condition",
        "attack_id",
        "target_asset",
        "resource_integrity_preserved",
        "protected_file_modified",
        "protected_file_deleted",
        "canary_observed",
        "canary_exfiltrated",
    ]


def _log_row(result: AttackTrialResult) -> dict[str, Any]:
    return {
        "condition": result.condition,
        "attack_id": result.attack_id,
        "log_exists": "accountability_log" not in result.resource_integrity_after.get("files", {}) or result.resource_integrity_after.get("files", {}).get("accountability_log", {}).get("exists", True),
        "log_chain_valid_before": result.log_chain_valid_before,
        "log_chain_valid_after": result.log_chain_valid_after,
        "tampering_attempted": result.tampering_attempted,
        "tampering_detected": result.tampering_detected,
        "silent_log_corruption": result.silent_log_corruption,
    }


def _network_row(result: AttackTrialResult) -> dict[str, Any]:
    return {
        "condition": result.condition,
        "attack_id": result.attack_id,
        "attempted_destination": result.attempted_destination,
        "allowed_peer_received": result.allowed_peer_received,
        "unauthorized_exfil_received": result.unauthorized_network_received,
        "canary_received_by_unauthorized_sink": result.canary_received_by_unauthorized_sink,
        "network_blocked": result.network_blocked,
    }


def _resource_row(result: AttackTrialResult) -> dict[str, Any]:
    return {
        "condition": result.condition,
        "attack_id": result.attack_id,
        "target_asset": result.target_asset,
        "resource_integrity_preserved": result.resource_integrity_preserved,
        "protected_file_modified": result.protected_file_modified,
        "protected_file_deleted": result.protected_file_deleted,
        "canary_observed": result.canary_observed,
        "canary_exfiltrated": result.canary_exfiltrated,
    }

