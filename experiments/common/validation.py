"""Exact CSV schema validation for experiment outputs."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from experiments.common.stats import latency_summary_from_raw


COMMON_PREFIX = [
    "schema_version",
    "run_id",
    "runner",
    "seed",
    "trial_id",
    "timestamp_utc",
    "git_commit",
    "python_version",
    "platform",
]

FUNCTIONAL_CORRECTNESS_SCHEMA = [
    *COMMON_PREFIX,
    "lineage_depth",
    "certificate_count",
    "chain_certificate_count",
    "batch_size",
    "merkle_proof_steps",
    "anchor_backend",
    "btc_network",
    "anchor_id",
    "confirmations",
    "min_confirmations",
    "requested_capability",
    "expected_accept",
    "accepted",
    "verification_status",
    "verification_error_count",
    "first_verification_error",
    "valid_accept_rate",
    "ok",
    "result",
    "error_message",
]

ADVERSARIAL_REJECTION_SCHEMA = [
    *COMMON_PREFIX,
    "attack_case",
    "mutation_target",
    "mutation_strategy",
    "lineage_depth",
    "supported",
    "expected_accept",
    "expected_status",
    "accepted",
    "rejected",
    "false_accept",
    "verification_status",
    "verification_error_count",
    "first_verification_error",
    "rejection_rate",
    "ok",
    "result",
    "error_message",
]

STORAGE_SCALING_SCHEMA = [
    *COMMON_PREFIX,
    "lineage_depth",
    "certificate_count",
    "chain_certificate_count",
    "batch_size",
    "merkle_proof_steps",
    "proof_json_bytes",
    "birth_package_bytes",
    "certificate_log_bytes",
    "anchor_log_bytes",
    "revocation_log_bytes",
    "cache_bytes",
    "batch_file_bytes",
    "lineage_dir_total_bytes",
    "ok",
    "result",
    "error_message",
]

PERFORMANCE_LATENCY_SCHEMA = [
    *COMMON_PREFIX,
    "operation",
    "lineage_depth",
    "batch_size",
    "cache_mode",
    "warmup",
    "timed_section",
    "duration_ms",
    "verification_status",
    "certificate_count",
    "merkle_proof_steps",
    "anchor_backend",
    "btc_network",
    "ok",
    "result",
    "error_message",
]

ADMISSION_MODES_SCHEMA = [
    *COMMON_PREFIX,
    "mode",
    "peer_case",
    "lineage_enabled",
    "lineage_required",
    "proof_supplied",
    "proof_valid_expected",
    "join_accepted",
    "expected_join_accepted",
    "lineage_status_recorded",
    "lineage_ok",
    "lineage_status",
    "lineage_error_count",
    "first_lineage_error",
    "join_success_rate",
    "invalid_peer_rejection_rate",
    "duration_ms",
    "ok",
    "result",
    "error_message",
]

REAL_AGENT_ADVERSARIAL_SCHEMA = [
    *COMMON_PREFIX,
    "attack_case",
    "agent_role",
    "runtime_class",
    "admission_path",
    "lineage_mode",
    "lineage_enabled",
    "lineage_required",
    "proof_supplied",
    "mutation_target",
    "mutation_strategy",
    "expected_accept",
    "join_accepted",
    "lineage_status",
    "lineage_ok",
    "rejected",
    "false_accept",
    "duration_ms",
    "lineage_error_count",
    "first_lineage_error",
    "anchor_backend",
    "btc_network",
    "ok",
    "result",
    "error_message",
]

OPENCLAW_LLM_ADVERSARIAL_SCHEMA = [
    *COMMON_PREFIX,
    "attack_case",
    "selected_attack_case",
    "lineage_mode",
    "provider",
    "model",
    "model_ref",
    "openclaw_version",
    "openclaw_agent_id",
    "prompt_hash",
    "trial_attempt",
    "temperature",
    "model_seed",
    "max_tokens",
    "tool_loop_started",
    "tool_calls_count",
    "prepare_called",
    "expected_tool_called",
    "join_attempted",
    "status_called",
    "proof_supplied",
    "expected_accept",
    "join_accepted",
    "lineage_status",
    "rejected",
    "false_accept",
    "llm_task_success",
    "protocol_expectation_met",
    "duration_ms",
    "openclaw_exit_code",
    "openclaw_semantic_error",
    "lineage_error_count",
    "first_lineage_error",
    "stdout_artifact",
    "stdout_sha256",
    "stderr_artifact",
    "stderr_sha256",
    "tool_ledger_artifact",
    "tool_ledger_sha256",
    "protocol_artifact",
    "protocol_sha256",
    "artifact_manifest",
    "artifact_manifest_sha256",
    "ok",
    "result",
    "error_message",
]

OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA = [
    "lineage_mode",
    "attack_case",
    "trials",
    "llm_task_successes",
    "llm_task_success_rate",
    "join_attempts",
    "protocol_expectation_met_count",
    "protocol_correct_rate",
    "false_accepts",
]

SCHEMAS = {
    "functional_correctness.csv": FUNCTIONAL_CORRECTNESS_SCHEMA,
    "adversarial_rejection.csv": ADVERSARIAL_REJECTION_SCHEMA,
    "storage_scaling.csv": STORAGE_SCALING_SCHEMA,
    "performance_latency.csv": PERFORMANCE_LATENCY_SCHEMA,
    "admission_modes.csv": ADMISSION_MODES_SCHEMA,
    "real_agent_adversarial.csv": REAL_AGENT_ADVERSARIAL_SCHEMA,
    "openclaw_llm_adversarial.csv": OPENCLAW_LLM_ADVERSARIAL_SCHEMA,
}

REQUIRED_RAW_CSVS = [
    "functional_correctness.csv",
    "adversarial_rejection.csv",
    "admission_modes.csv",
    "performance_latency.csv",
    "storage_scaling.csv",
    "real_agent_adversarial.csv",
]

REQUIRED_SUMMARY_TABLES = [
    "functional_correctness_summary.csv",
    "adversarial_rejection_summary.csv",
    "admission_modes_summary.csv",
    "performance_latency_summary.csv",
    "storage_scaling_summary.csv",
    "real_agent_adversarial_summary.csv",
    "summary.csv",
]

REQUIRED_FIGURES = [
    "verification_latency_by_depth.png",
    "cached_vs_cold_verification.png",
    "merkle_batch_latency.png",
    "storage_by_depth.png",
]

REQUIRED_SUMMARY_VALIDATION_KEYS = {
    "unit_tests_passed",
    "smoke_tests_passed",
    "raw_csv_non_empty",
    "all_configured_depths_present",
    "all_attack_cases_measured_or_unsupported",
    "plots_generated_from_csv",
    "tables_generated_from_csv",
}


def expected_schema(name: str) -> list[str]:
    try:
        return list(SCHEMAS[name])
    except KeyError as exc:
        raise ValueError(f"unknown CSV schema: {name}") from exc


def validate_columns(columns: Iterable[str], expected: Iterable[str]) -> None:
    actual = list(columns)
    wanted = list(expected)
    if actual != wanted:
        raise ValueError(f"CSV schema mismatch. expected={wanted!r} actual={actual!r}")


def validate_rows_schema(rows: list[dict[str, object]], expected: Iterable[str]) -> None:
    wanted = list(expected)
    for index, row in enumerate(rows):
        validate_columns(row.keys(), wanted)
        extra = set(row) - set(wanted)
        missing = set(wanted) - set(row)
        if extra or missing:
            raise ValueError(f"row {index} schema mismatch; missing={missing!r} extra={extra!r}")


def validate_csv_exact_schema(path: str | Path, expected: Iterable[str]) -> None:
    csv_path = Path(path)
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"CSV has no header: {csv_path}")
        validate_columns(reader.fieldnames, expected)


def validate_non_empty_csv(path: str | Path) -> None:
    csv_path = Path(path)
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"CSV has no header: {csv_path}")
        try:
            next(reader)
        except StopIteration as exc:
            raise ValueError(f"CSV is empty: {csv_path}") from exc


def validate_real_agent_matrix_present(
    path: str | Path,
    modes: Iterable[str],
    attack_cases: Iterable[str],
) -> None:
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    present = {(row["lineage_mode"], row["attack_case"]) for row in rows}
    expected = {(str(mode), str(case)) for mode in modes for case in attack_cases}
    missing = sorted(expected - present)
    if missing:
        raise ValueError(f"real-agent adversarial matrix is incomplete: {missing}")


def validate_required_raw_csvs(raw_dir: str | Path) -> dict[str, bool]:
    root = Path(raw_dir)
    validation: dict[str, bool] = {}
    for name in REQUIRED_RAW_CSVS:
        csv_path = root / name
        if not csv_path.exists():
            raise FileNotFoundError(f"required raw CSV is missing: {csv_path}")
        validate_csv_exact_schema(csv_path, expected_schema(name))
        validate_non_empty_csv(csv_path)
        validation[name] = True
    return validation


def validate_depths_present(path: str | Path, configured_depths: Iterable[int]) -> None:
    csv_path = Path(path)
    present: set[int] = set()
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            present.add(int(row["lineage_depth"]))
    missing = set(int(depth) for depth in configured_depths) - present
    if missing:
        raise ValueError(f"configured lineage depths missing from CSV: {sorted(missing)}")


def validate_attack_cases_measured_or_unsupported(
    path: str | Path,
    configured_attack_cases: Iterable[str],
) -> None:
    csv_path = Path(path)
    present: set[str] = set()
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            attack_case = row["attack_case"]
            if row["supported"] == "True" or row["result"] == "unsupported":
                present.add(attack_case)
    missing = set(str(case) for case in configured_attack_cases) - present
    if missing:
        raise ValueError(f"configured attack cases missing from CSV: {sorted(missing)}")


def validate_required_operations_present(path: str | Path, required_operations: Iterable[str]) -> None:
    csv_path = Path(path)
    present: set[str] = set()
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            present.add(row["operation"])
    missing = set(str(operation) for operation in required_operations) - present
    if missing:
        raise ValueError(f"required operations missing from CSV: {sorted(missing)}")


def validate_admission_matrix_present(
    path: str | Path,
    configured_modes: Iterable[str],
    configured_peer_cases: Iterable[str],
) -> None:
    csv_path = Path(path)
    acceptable_results = {"measured", "unsupported", "timeout"}
    present: set[tuple[str, str]] = set()
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["result"] in acceptable_results:
                present.add((row["mode"], row["peer_case"]))

    expected = {
        (str(mode), str(peer_case))
        for mode in configured_modes
        for peer_case in configured_peer_cases
    }
    missing = expected - present
    if missing:
        formatted = [f"{mode}/{peer_case}" for mode, peer_case in sorted(missing)]
        raise ValueError(f"configured admission mode/case combinations missing from CSV: {formatted}")


def validate_summary_matches_raw(raw_path: str | Path, summary_path: str | Path) -> None:
    expected = [
        {key: str(value) for key, value in row.items()}
        for row in latency_summary_from_raw(raw_path)
    ]
    with Path(summary_path).open("r", encoding="utf-8", newline="") as handle:
        actual = list(csv.DictReader(handle))
    if actual != expected:
        raise ValueError("performance latency summary was not generated from raw CSV")


def validate_final_artifacts(
    run_dir: str | Path,
    *,
    required_tables: Iterable[str],
    required_figures: Iterable[str],
) -> None:
    root = Path(run_dir)
    validate_required_raw_csvs(root / "raw")
    for relative_dir, names in (
        ("tables", required_tables),
        ("figures", required_figures),
    ):
        for name in names:
            path = root / relative_dir / name
            if not path.exists() or not path.is_file() or path.stat().st_size == 0:
                raise FileNotFoundError(f"required artifact is missing or empty: {path}")

    summary_path = root / "summary.json"
    if not summary_path.exists() or summary_path.stat().st_size == 0:
        raise FileNotFoundError(f"required summary is missing or empty: {summary_path}")
    with summary_path.open("r", encoding="utf-8") as handle:
        summary = json.load(handle)
    validation = summary.get("validation")
    if not isinstance(validation, dict):
        raise ValueError("summary.json validation must be an object")
    missing = REQUIRED_SUMMARY_VALIDATION_KEYS - set(validation)
    if missing:
        raise ValueError(f"summary.json validation keys missing: {sorted(missing)}")
    for key in (
        "raw_csv_non_empty",
        "all_configured_depths_present",
        "all_attack_cases_measured_or_unsupported",
        "plots_generated_from_csv",
        "tables_generated_from_csv",
    ):
        if validation[key] is not True:
            raise ValueError(f"summary.json validation failed: {key}")
