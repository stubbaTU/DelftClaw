"""Generate derived tables, figures, and run summary metadata from raw CSVs.

This phase consumes completed mock-anchored experiment outputs only. It does not
run experiments, call the lineage verifier, or add external Bitcoin measurements.
"""

from __future__ import annotations

import argparse
import platform
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from experiments.common.environment import capture_environment
from experiments.common.io import read_csv, read_json, utc_timestamp, write_csv, write_json
from experiments.common.stats import (
    PERFORMANCE_LATENCY_SUMMARY_SCHEMA,
    SUMMARY_CSV_SCHEMA,
    boolean_count,
    grouped_rows,
    latency_summary_from_raw,
    numeric_values,
    result_count,
    stats_or_empty,
    summary,
)
from experiments.common.validation import (
    REQUIRED_RAW_CSVS,
    validate_admission_matrix_present,
    validate_attack_cases_measured_or_unsupported,
    validate_csv_exact_schema,
    validate_depths_present,
    validate_non_empty_csv,
    validate_required_operations_present,
    validate_required_raw_csvs,
    validate_real_agent_matrix_present,
    validate_summary_matches_raw,
)


FUNCTIONAL_SUMMARY_SCHEMA = [
    "lineage_depth",
    "trial_count",
    "success_count",
    "failure_count",
    "accepted_count",
    "valid_accept_rate",
    "certificate_count_mean",
    "certificate_count_min",
    "certificate_count_max",
    "merkle_proof_steps_mean",
    "merkle_proof_steps_min",
    "merkle_proof_steps_max",
]

ADVERSARIAL_SUMMARY_SCHEMA = [
    "attack_case",
    "expected_status",
    "trial_count",
    "supported_count",
    "unsupported_count",
    "rejected_count",
    "false_accept_count",
    "failure_count",
    "rejection_rate",
]

ADMISSION_SUMMARY_SCHEMA = [
    "mode",
    "peer_case",
    "trial_count",
    "success_count",
    "failure_count",
    "unsupported_count",
    "timeout_count",
    "join_success_rate",
    "invalid_peer_rejection_rate",
    "duration_ms_mean",
    "duration_ms_stddev",
    "duration_ms_min",
    "duration_ms_p50",
    "duration_ms_p95",
    "duration_ms_p99",
    "duration_ms_max",
]

REAL_AGENT_ADVERSARIAL_SUMMARY_SCHEMA = [
    "lineage_mode",
    "attack_case",
    "trial_count",
    "success_count",
    "failure_count",
    "join_accepted_count",
    "rejected_count",
    "false_accept_count",
    "join_accept_rate",
    "rejection_rate",
    "duration_ms_mean",
    "duration_ms_p50",
    "duration_ms_p95",
    "duration_ms_max",
]

STORAGE_SUMMARY_SCHEMA = [
    "lineage_depth",
    "metric",
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

REQUIRED_OPERATIONS = [
    "certificate_issue",
    "merkle_root_build",
    "merkle_proof_build",
    "mock_anchor_create",
    "verify_cold",
    "verify_cached",
]

STORAGE_SIZE_METRICS = [
    "proof_json_bytes",
    "lineage_dir_total_bytes",
    "birth_package_bytes",
    "certificate_log_bytes",
    "anchor_log_bytes",
    "batch_file_bytes",
    "cache_bytes",
]


def _truthy(value: object) -> bool:
    return value in {True, "True", "true", "1", 1}


def _float_or_empty(value: float | str) -> float | str:
    return value


def _run_id(run_dir: Path) -> str:
    return run_dir.name


def _schema_version(config: dict, rows_by_csv: dict[str, list[dict[str, str]]]) -> str:
    if "schema_version" in config:
        return str(config["schema_version"])
    for rows in rows_by_csv.values():
        if rows:
            return rows[0].get("schema_version", "1") or "1"
    return "1"


def _git_commit(environment: dict, rows_by_csv: dict[str, list[dict[str, str]]]) -> str:
    if environment.get("git_commit"):
        return str(environment["git_commit"])
    for rows in rows_by_csv.values():
        if rows:
            return rows[0].get("git_commit", "unavailable") or "unavailable"
    return "unavailable"


def _metadata_row(
    *,
    schema_version: str,
    run_id: str,
    timestamp_utc: str,
    git_commit: str,
    runner: str,
    metric: str,
    group_key: str,
    group_value: str,
    rows: list[dict[str, str]],
    values: list[float] | None,
    unit: str,
    source_csv: str,
) -> dict[str, object]:
    stats = stats_or_empty(values or [])
    return {
        "schema_version": schema_version,
        "run_id": run_id,
        "timestamp_utc": timestamp_utc,
        "git_commit": git_commit,
        "runner": runner,
        "metric": metric,
        "group_key": group_key,
        "group_value": group_value,
        "trial_count": len(rows),
        "success_count": boolean_count(rows, "ok", True),
        "failure_count": boolean_count(rows, "ok", False),
        "unsupported_count": result_count(rows, "unsupported"),
        "mean": stats["mean"],
        "stddev": stats["stddev"],
        "min": stats["min"],
        "p50": stats["p50"],
        "p95": stats["p95"],
        "p99": stats["p99"],
        "max": stats["max"],
        "unit": unit,
        "source_csv": source_csv,
    }


def _count_metric_row(
    *,
    schema_version: str,
    run_id: str,
    timestamp_utc: str,
    git_commit: str,
    runner: str,
    metric: str,
    group_key: str,
    group_value: str,
    rows: list[dict[str, str]],
    value: int | float,
    source_csv: str,
) -> dict[str, object]:
    row = _metadata_row(
        schema_version=schema_version,
        run_id=run_id,
        timestamp_utc=timestamp_utc,
        git_commit=git_commit,
        runner=runner,
        metric=metric,
        group_key=group_key,
        group_value=group_value,
        rows=rows,
        values=[],
        unit="count",
        source_csv=source_csv,
    )
    row["mean"] = value
    return row


def _load_optional_json(path: Path, fallback: dict | None = None) -> dict:
    if not path.exists():
        return dict(fallback or {})
    data = read_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object: {path}")
    return data


def _write_functional_summary(
    rows: list[dict[str, str]],
    path: Path,
    summary_rows: list[dict[str, object]],
    meta: dict[str, str],
) -> dict[str, float]:
    output: list[dict[str, object]] = []
    accept_rates: dict[str, float] = {}
    for (depth,), group in sorted(grouped_rows(rows, ["lineage_depth"]).items(), key=lambda item: int(item[0][0])):
        certificate = numeric_values(group, "certificate_count")
        proof_steps = numeric_values(group, "merkle_proof_steps")
        accepts = numeric_values(group, "valid_accept_rate")
        accept_rate = summary(accepts)["mean"] if accepts else 0.0
        accept_rates[depth] = accept_rate
        output.append({
            "lineage_depth": depth,
            "trial_count": len(group),
            "success_count": boolean_count(group, "ok", True),
            "failure_count": boolean_count(group, "ok", False),
            "accepted_count": boolean_count(group, "accepted", True),
            "valid_accept_rate": accept_rate,
            "certificate_count_mean": summary(certificate)["mean"] if certificate else "",
            "certificate_count_min": min(certificate) if certificate else "",
            "certificate_count_max": max(certificate) if certificate else "",
            "merkle_proof_steps_mean": summary(proof_steps)["mean"] if proof_steps else "",
            "merkle_proof_steps_min": min(proof_steps) if proof_steps else "",
            "merkle_proof_steps_max": max(proof_steps) if proof_steps else "",
        })
        summary_rows.extend([
            _metadata_row(**meta, runner="functional_correctness", metric="valid_accept_rate", group_key="lineage_depth", group_value=depth, rows=group, values=accepts, unit="rate", source_csv="functional_correctness.csv"),
            _count_metric_row(**meta, runner="functional_correctness", metric="trial_count", group_key="lineage_depth", group_value=depth, rows=group, value=len(group), source_csv="functional_correctness.csv"),
            _count_metric_row(**meta, runner="functional_correctness", metric="success_count", group_key="lineage_depth", group_value=depth, rows=group, value=boolean_count(group, "ok", True), source_csv="functional_correctness.csv"),
            _count_metric_row(**meta, runner="functional_correctness", metric="failure_count", group_key="lineage_depth", group_value=depth, rows=group, value=boolean_count(group, "ok", False), source_csv="functional_correctness.csv"),
            _metadata_row(**meta, runner="functional_correctness", metric="certificate_count", group_key="lineage_depth", group_value=depth, rows=group, values=certificate, unit="count", source_csv="functional_correctness.csv"),
            _metadata_row(**meta, runner="functional_correctness", metric="merkle_proof_steps", group_key="lineage_depth", group_value=depth, rows=group, values=proof_steps, unit="count", source_csv="functional_correctness.csv"),
        ])
    write_csv(path, output, FUNCTIONAL_SUMMARY_SCHEMA)
    return accept_rates


def _write_adversarial_summary(
    rows: list[dict[str, str]],
    path: Path,
    summary_rows: list[dict[str, object]],
    meta: dict[str, str],
) -> dict[str, float]:
    output: list[dict[str, object]] = []
    rates: dict[str, float] = {}
    for (attack_case,), group in sorted(grouped_rows(rows, ["attack_case"]).items()):
        expected = sorted({row["expected_status"] for row in group if row["expected_status"]})
        rejection_values = numeric_values(group, "rejection_rate")
        rejection_rate = summary(rejection_values)["mean"] if rejection_values else ""
        if rejection_rate != "":
            rates[attack_case] = float(rejection_rate)
        output.append({
            "attack_case": attack_case,
            "expected_status": ";".join(expected),
            "trial_count": len(group),
            "supported_count": boolean_count(group, "supported", True),
            "unsupported_count": result_count(group, "unsupported"),
            "rejected_count": boolean_count(group, "rejected", True),
            "false_accept_count": boolean_count(group, "false_accept", True),
            "failure_count": boolean_count(group, "ok", False),
            "rejection_rate": rejection_rate,
        })
        summary_rows.extend([
            _metadata_row(**meta, runner="adversarial_rejection", metric="rejection_rate", group_key="attack_case", group_value=attack_case, rows=group, values=rejection_values, unit="rate", source_csv="adversarial_rejection.csv"),
            _count_metric_row(**meta, runner="adversarial_rejection", metric="false_accept_count", group_key="attack_case", group_value=attack_case, rows=group, value=boolean_count(group, "false_accept", True), source_csv="adversarial_rejection.csv"),
            _count_metric_row(**meta, runner="adversarial_rejection", metric="unsupported_count", group_key="attack_case", group_value=attack_case, rows=group, value=result_count(group, "unsupported"), source_csv="adversarial_rejection.csv"),
            _count_metric_row(**meta, runner="adversarial_rejection", metric="trial_count", group_key="attack_case", group_value=attack_case, rows=group, value=len(group), source_csv="adversarial_rejection.csv"),
        ])
    write_csv(path, output, ADVERSARIAL_SUMMARY_SCHEMA)
    return rates


def _write_admission_summary(
    rows: list[dict[str, str]],
    path: Path,
    summary_rows: list[dict[str, object]],
    meta: dict[str, str],
) -> dict[str, float]:
    output: list[dict[str, object]] = []
    rates: dict[str, float] = {}
    groups = grouped_rows(rows, ["mode", "peer_case"])
    for (mode, peer_case), group in sorted(groups.items()):
        durations = numeric_values(group, "duration_ms")
        duration_stats = stats_or_empty(durations)
        join_values = numeric_values(group, "join_success_rate")
        rejection_values = numeric_values(group, "invalid_peer_rejection_rate")
        join_rate = summary(join_values)["mean"] if join_values else ""
        rejection_rate = summary(rejection_values)["mean"] if rejection_values else ""
        rates[f"{mode}/{peer_case}"] = float(join_rate) if join_rate != "" else 0.0
        output.append({
            "mode": mode,
            "peer_case": peer_case,
            "trial_count": len(group),
            "success_count": boolean_count(group, "ok", True),
            "failure_count": boolean_count(group, "ok", False),
            "unsupported_count": result_count(group, "unsupported"),
            "timeout_count": result_count(group, "timeout"),
            "join_success_rate": join_rate,
            "invalid_peer_rejection_rate": rejection_rate,
            "duration_ms_mean": duration_stats["mean"],
            "duration_ms_stddev": duration_stats["stddev"],
            "duration_ms_min": duration_stats["min"],
            "duration_ms_p50": duration_stats["p50"],
            "duration_ms_p95": duration_stats["p95"],
            "duration_ms_p99": duration_stats["p99"],
            "duration_ms_max": duration_stats["max"],
        })
        group_value = f"{mode}/{peer_case}"
        summary_rows.extend([
            _metadata_row(**meta, runner="admission_modes", metric="join_success_rate", group_key="mode_peer_case", group_value=group_value, rows=group, values=join_values, unit="rate", source_csv="admission_modes.csv"),
            _metadata_row(**meta, runner="admission_modes", metric="invalid_peer_rejection_rate", group_key="mode_peer_case", group_value=group_value, rows=group, values=rejection_values, unit="rate", source_csv="admission_modes.csv"),
            _count_metric_row(**meta, runner="admission_modes", metric="timeout_count", group_key="mode_peer_case", group_value=group_value, rows=group, value=result_count(group, "timeout"), source_csv="admission_modes.csv"),
            _count_metric_row(**meta, runner="admission_modes", metric="unsupported_count", group_key="mode_peer_case", group_value=group_value, rows=group, value=result_count(group, "unsupported"), source_csv="admission_modes.csv"),
            _metadata_row(**meta, runner="admission_modes", metric="duration_ms", group_key="mode_peer_case", group_value=group_value, rows=group, values=durations, unit="ms", source_csv="admission_modes.csv"),
        ])
    write_csv(path, output, ADMISSION_SUMMARY_SCHEMA)
    return rates


def _write_real_agent_adversarial_summary(
    rows: list[dict[str, str]],
    path: Path,
    summary_rows: list[dict[str, object]],
    meta: dict[str, str],
) -> dict[str, float]:
    output: list[dict[str, object]] = []
    rates: dict[str, float] = {}
    for (mode, attack_case), group in sorted(grouped_rows(rows, ["lineage_mode", "attack_case"]).items()):
        trial_count = len(group)
        join_count = boolean_count(group, "join_accepted", True)
        rejected_count = boolean_count(group, "rejected", True)
        false_accept_count = boolean_count(group, "false_accept", True)
        join_rate = join_count / trial_count if trial_count else 0.0
        rejection_rate = rejected_count / trial_count if trial_count else 0.0
        durations = numeric_values(group, "duration_ms")
        duration_stats = stats_or_empty(durations)
        group_value = f"{mode}/{attack_case}"
        rates[group_value] = rejection_rate
        output.append({
            "lineage_mode": mode,
            "attack_case": attack_case,
            "trial_count": trial_count,
            "success_count": boolean_count(group, "ok", True),
            "failure_count": boolean_count(group, "ok", False),
            "join_accepted_count": join_count,
            "rejected_count": rejected_count,
            "false_accept_count": false_accept_count,
            "join_accept_rate": join_rate,
            "rejection_rate": rejection_rate,
            "duration_ms_mean": duration_stats["mean"],
            "duration_ms_p50": duration_stats["p50"],
            "duration_ms_p95": duration_stats["p95"],
            "duration_ms_max": duration_stats["max"],
        })
        summary_rows.extend([
            _metadata_row(
                **meta,
                runner="real_agent_adversarial",
                metric="duration_ms",
                group_key="mode_attack_case",
                group_value=group_value,
                rows=group,
                values=durations,
                unit="ms",
                source_csv="real_agent_adversarial.csv",
            ),
            _count_metric_row(
                **meta,
                runner="real_agent_adversarial",
                metric="rejected_count",
                group_key="mode_attack_case",
                group_value=group_value,
                rows=group,
                value=rejected_count,
                source_csv="real_agent_adversarial.csv",
            ),
            _count_metric_row(
                **meta,
                runner="real_agent_adversarial",
                metric="false_accept_count",
                group_key="mode_attack_case",
                group_value=group_value,
                rows=group,
                value=false_accept_count,
                source_csv="real_agent_adversarial.csv",
            ),
        ])
    write_csv(path, output, REAL_AGENT_ADVERSARIAL_SUMMARY_SCHEMA)
    return rates


def _write_performance_summary(
    raw_path: Path,
    path: Path,
    summary_rows: list[dict[str, object]],
    meta: dict[str, str],
) -> dict[str, float]:
    rows = latency_summary_from_raw(raw_path)
    write_csv(path, rows, PERFORMANCE_LATENCY_SUMMARY_SCHEMA)
    validate_csv_exact_schema(path, PERFORMANCE_LATENCY_SUMMARY_SCHEMA)
    validate_non_empty_csv(path)
    validate_summary_matches_raw(raw_path, path)

    metrics: dict[str, float] = {}
    raw_rows = read_csv(raw_path)
    measured_groups = grouped_rows(
        [
            row
            for row in raw_rows
            if row["warmup"] == "False" and row["ok"] == "True" and row["duration_ms"] != ""
        ],
        ["operation", "lineage_depth", "batch_size", "cache_mode", "timed_section"],
    )
    for key, group in sorted(measured_groups.items()):
        operation, depth, batch_size, cache_mode, timed_section = key
        values = numeric_values(group, "duration_ms")
        group_value = "/".join([operation, depth or "none", batch_size or "none", cache_mode, timed_section])
        p50 = summary(values)["p50"] if values else 0.0
        metrics[group_value] = p50
        summary_rows.append(
            _metadata_row(
                **meta,
                runner="performance_latency",
                metric="duration_ms",
                group_key="operation_depth_batch_cache_section",
                group_value=group_value,
                rows=group,
                values=values,
                unit="ms",
                source_csv="performance_latency.csv",
            )
        )
    return metrics


def _write_storage_summary(
    rows: list[dict[str, str]],
    path: Path,
    summary_rows: list[dict[str, object]],
    meta: dict[str, str],
) -> dict[str, dict[str, float]]:
    output: list[dict[str, object]] = []
    metrics: dict[str, dict[str, float]] = defaultdict(dict)
    for (depth,), group in sorted(grouped_rows(rows, ["lineage_depth"]).items(), key=lambda item: int(item[0][0])):
        for metric in STORAGE_SIZE_METRICS:
            values = numeric_values(group, metric)
            stats = stats_or_empty(values)
            output.append({
                "lineage_depth": depth,
                "metric": metric,
                "trial_count": len(values),
                "mean": stats["mean"],
                "stddev": stats["stddev"],
                "min": stats["min"],
                "p50": stats["p50"],
                "p95": stats["p95"],
                "p99": stats["p99"],
                "max": stats["max"],
                "unit": "bytes",
            })
            if stats["mean"] != "":
                metrics[metric][depth] = float(stats["mean"])
            summary_rows.append(
                _metadata_row(
                    **meta,
                    runner="storage_scaling",
                    metric=metric,
                    group_key="lineage_depth",
                    group_value=depth,
                    rows=group,
                    values=values,
                    unit="bytes",
                    source_csv="storage_scaling.csv",
                )
            )
    write_csv(path, output, STORAGE_SUMMARY_SCHEMA)
    return dict(metrics)


def _aggregate_xy(
    rows: Iterable[dict[str, str]],
    *,
    x_column: str,
    y_column: str,
) -> tuple[list[float], list[float]]:
    buckets: dict[float, list[float]] = defaultdict(list)
    for row in rows:
        x_value = row.get(x_column, "")
        y_value = row.get(y_column, "")
        if x_value == "" or y_value == "":
            continue
        buckets[float(x_value)].append(float(y_value))
    xs: list[float] = []
    ys: list[float] = []
    for x_value in sorted(buckets):
        xs.append(x_value)
        ys.append(summary(buckets[x_value])["p50"])
    if not xs:
        raise ValueError(f"no plot data for {x_column}/{y_column}")
    return xs, ys


def _plot_line(path: Path, *, title: str, xlabel: str, ylabel: str, series: list[tuple[str, list[float], list[float]]]) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(7, 4.5))
    for label, xs, ys in series:
        ax.plot(xs, ys, marker="o", label=label)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    if len(series) > 1:
        ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160)
    plt.close(fig)


def _write_figures(performance_rows: list[dict[str, str]], storage_rows: list[dict[str, str]], figures_dir: Path) -> dict[str, Path]:
    outputs = {
        "verification_latency_by_depth": figures_dir / "verification_latency_by_depth.png",
        "cached_vs_cold_verification": figures_dir / "cached_vs_cold_verification.png",
        "merkle_batch_latency": figures_dir / "merkle_batch_latency.png",
        "storage_by_depth": figures_dir / "storage_by_depth.png",
    }
    measured = [row for row in performance_rows if row["warmup"] == "False" and row["ok"] == "True"]
    cold = [row for row in measured if row["operation"] == "verify_cold"]
    cached = [row for row in measured if row["operation"] == "verify_cached"]
    merkle = [row for row in measured if row["operation"] in {"merkle_root_build", "merkle_proof_build"}]

    cold_x, cold_y = _aggregate_xy(cold, x_column="lineage_depth", y_column="duration_ms")
    _plot_line(
        outputs["verification_latency_by_depth"],
        title="Verification latency by lineage depth",
        xlabel="Lineage depth",
        ylabel="Duration p50 (ms)",
        series=[("verify_cold", cold_x, cold_y)],
    )

    cached_x, cached_y = _aggregate_xy(cached, x_column="lineage_depth", y_column="duration_ms")
    _plot_line(
        outputs["cached_vs_cold_verification"],
        title="Cached vs cold verification latency",
        xlabel="Lineage depth",
        ylabel="Duration p50 (ms)",
        series=[("verify_cold", cold_x, cold_y), ("verify_cached", cached_x, cached_y)],
    )

    merkle_series: list[tuple[str, list[float], list[float]]] = []
    for operation in ("merkle_root_build", "merkle_proof_build"):
        op_rows = [row for row in merkle if row["operation"] == operation]
        xs, ys = _aggregate_xy(op_rows, x_column="batch_size", y_column="duration_ms")
        merkle_series.append((operation, xs, ys))
    _plot_line(
        outputs["merkle_batch_latency"],
        title="Merkle batch latency",
        xlabel="Batch size",
        ylabel="Duration p50 (ms)",
        series=merkle_series,
    )

    storage_series: list[tuple[str, list[float], list[float]]] = []
    for metric in ("proof_json_bytes", "lineage_dir_total_bytes"):
        xs, ys = _aggregate_xy(storage_rows, x_column="lineage_depth", y_column=metric)
        storage_series.append((metric, xs, ys))
    _plot_line(
        outputs["storage_by_depth"],
        title="Storage by lineage depth",
        xlabel="Lineage depth",
        ylabel="Bytes p50",
        series=storage_series,
    )
    return outputs


def _configured_depths_present(config: dict, rows_by_csv: dict[str, list[dict[str, str]]]) -> bool:
    depths = {int(depth) for depth in config.get("depths", [])}
    performance_depths = {int(depth) for depth in config.get("performance_depths", [])}
    if depths:
        for name in ("functional_correctness.csv", "storage_scaling.csv"):
            present = {int(row["lineage_depth"]) for row in rows_by_csv[name] if row.get("lineage_depth")}
            if not depths.issubset(present):
                return False
    if performance_depths:
        present = {
            int(row["lineage_depth"])
            for row in rows_by_csv["performance_latency.csv"]
            if row.get("operation") in {"verify_cold", "verify_cached"} and row.get("lineage_depth")
        }
        if not performance_depths.issubset(present):
            return False
    return True


def _attack_cases_present(config: dict, adversarial_path: Path) -> bool:
    cases = config.get("adversarial_attack_cases", [])
    if not cases:
        return True
    try:
        validate_attack_cases_measured_or_unsupported(adversarial_path, cases)
    except ValueError:
        return False
    return True


def _validate_configured_content(config: dict, raw_dir: Path) -> dict[str, bool]:
    result: dict[str, bool] = {}
    if config.get("depths"):
        for name in ("functional_correctness.csv", "storage_scaling.csv"):
            validate_depths_present(raw_dir / name, config["depths"])
    if config.get("adversarial_attack_cases"):
        validate_attack_cases_measured_or_unsupported(raw_dir / "adversarial_rejection.csv", config["adversarial_attack_cases"])
    if config.get("admission_modes") and config.get("admission_peer_cases"):
        validate_admission_matrix_present(raw_dir / "admission_modes.csv", config["admission_modes"], config["admission_peer_cases"])
    if config.get("real_agent_lineage_modes") and config.get("real_agent_attack_cases"):
        validate_real_agent_matrix_present(
            raw_dir / "real_agent_adversarial.csv",
            config["real_agent_lineage_modes"],
            config["real_agent_attack_cases"],
        )
    validate_required_operations_present(raw_dir / "performance_latency.csv", REQUIRED_OPERATIONS)
    result["configured_content_validated"] = True
    return result


def _path_map(paths: dict[str, Path] | list[Path]) -> dict[str, str]:
    if isinstance(paths, dict):
        return {key: str(path) for key, path in paths.items()}
    return {path.name: str(path) for path in paths}


def run(args: argparse.Namespace) -> Path:
    run_dir = Path(args.run_dir).resolve()
    raw_dir = run_dir / "raw"
    tables_dir = run_dir / "tables"
    figures_dir = run_dir / "figures"
    if not run_dir.exists():
        raise FileNotFoundError(f"run directory does not exist: {run_dir}")
    raw_validation = validate_required_raw_csvs(raw_dir)

    raw_paths = {name: raw_dir / name for name in REQUIRED_RAW_CSVS}
    rows_by_csv = {name: read_csv(path) for name, path in raw_paths.items()}

    config = _load_optional_json(run_dir / "config.json")
    environment = _load_optional_json(
        run_dir / "environment.json",
        fallback=capture_environment(Path(__file__).resolve().parents[1]),
    )
    configured_validation = _validate_configured_content(config, raw_dir)

    created_at_utc = utc_timestamp()
    metadata = {
        "schema_version": _schema_version(config, rows_by_csv),
        "run_id": _run_id(run_dir),
        "timestamp_utc": created_at_utc,
        "git_commit": _git_commit(environment, rows_by_csv),
    }

    summary_rows: list[dict[str, object]] = []
    table_paths = {
        "functional_correctness_summary.csv": tables_dir / "functional_correctness_summary.csv",
        "adversarial_rejection_summary.csv": tables_dir / "adversarial_rejection_summary.csv",
        "admission_modes_summary.csv": tables_dir / "admission_modes_summary.csv",
        "performance_latency_summary.csv": tables_dir / "performance_latency_summary.csv",
        "storage_scaling_summary.csv": tables_dir / "storage_scaling_summary.csv",
        "real_agent_adversarial_summary.csv": tables_dir / "real_agent_adversarial_summary.csv",
        "summary.csv": tables_dir / "summary.csv",
    }

    metrics = {
        "functional_valid_accept_rate_by_depth": _write_functional_summary(
            rows_by_csv["functional_correctness.csv"],
            table_paths["functional_correctness_summary.csv"],
            summary_rows,
            metadata,
        ),
        "adversarial_rejection_rate_by_attack_case": _write_adversarial_summary(
            rows_by_csv["adversarial_rejection.csv"],
            table_paths["adversarial_rejection_summary.csv"],
            summary_rows,
            metadata,
        ),
        "admission_join_success_rate_by_mode_peer_case": _write_admission_summary(
            rows_by_csv["admission_modes.csv"],
            table_paths["admission_modes_summary.csv"],
            summary_rows,
            metadata,
        ),
        "real_agent_rejection_rate_by_mode_attack_case": _write_real_agent_adversarial_summary(
            rows_by_csv["real_agent_adversarial.csv"],
            table_paths["real_agent_adversarial_summary.csv"],
            summary_rows,
            metadata,
        ),
        "performance_duration_p50_ms_by_operation_group": _write_performance_summary(
            raw_paths["performance_latency.csv"],
            table_paths["performance_latency_summary.csv"],
            summary_rows,
            metadata,
        ),
        "storage_mean_bytes_by_metric_and_depth": _write_storage_summary(
            rows_by_csv["storage_scaling.csv"],
            table_paths["storage_scaling_summary.csv"],
            summary_rows,
            metadata,
        ),
    }
    write_csv(table_paths["summary.csv"], summary_rows, SUMMARY_CSV_SCHEMA)
    validate_csv_exact_schema(table_paths["summary.csv"], SUMMARY_CSV_SCHEMA)
    validate_non_empty_csv(table_paths["summary.csv"])

    figure_paths = _write_figures(rows_by_csv["performance_latency.csv"], rows_by_csv["storage_scaling.csv"], figures_dir)
    for figure_path in figure_paths.values():
        if not figure_path.exists() or figure_path.stat().st_size == 0:
            raise ValueError(f"figure was not generated: {figure_path}")

    all_depths_present = _configured_depths_present(config, rows_by_csv)
    all_attack_cases_present = _attack_cases_present(config, raw_paths["adversarial_rejection.csv"])
    validation = {
        "unit_tests_passed": "unknown",
        "smoke_tests_passed": "unknown",
        "raw_csv_non_empty": all(raw_validation.values()),
        "all_configured_depths_present": all_depths_present,
        "all_attack_cases_measured_or_unsupported": all_attack_cases_present,
        "plots_generated_from_csv": True,
        "tables_generated_from_csv": True,
        **configured_validation,
    }

    summary_json = {
        "schema_version": metadata["schema_version"],
        "run_id": metadata["run_id"],
        "created_at_utc": created_at_utc,
        "repository_root": environment.get("repository_root", str(Path(__file__).resolve().parents[1])),
        "git_commit": metadata["git_commit"],
        "git_dirty": environment.get("git_dirty", "unknown"),
        "python_version": environment.get("python_version", platform.python_version()),
        "platform": environment.get("platform", platform.platform()),
        "os": environment.get("os", {"system": platform.system()}),
        "dependencies": environment.get("dependencies", {}),
        "config_path": config.get("config_path", str(run_dir / "config.json") if (run_dir / "config.json").exists() else ""),
        "config": config,
        "raw_outputs": _path_map(raw_paths),
        "table_outputs": _path_map(table_paths),
        "figure_outputs": _path_map(figure_paths),
        "validation": validation,
        "metrics": metrics,
        "claim_boundary": (
            "verifier-level and real OpenClawAgent/IPv8 admission experiments use "
            "mock anchor records; no Bitcoin RPC/regtest OP_RETURN anchoring"
        ),
    }
    run_summary_path = run_dir / "summary.json"
    write_json(run_summary_path, summary_json)

    top_level_summary = {
        "schema_version": metadata["schema_version"],
        "latest_run_path": str(run_dir),
        "run_id": metadata["run_id"],
        "created_at_utc": created_at_utc,
        "summary_path": str(run_summary_path),
    }
    write_json(run_dir.parents[1] / "summary.json", top_level_summary)
    return run_summary_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, help="Completed run directory containing all required raw CSVs.")
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        print(f"plot/table generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
