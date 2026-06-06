"""Run the complete mock-anchored lineage experiment pipeline."""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from typing import Callable

from experiments import (
    generate_plots_tables,
    run_adversarial_rejection,
    run_functional_correctness,
    run_performance_latency,
    run_storage_scaling,
)
from experiments.common.config import add_common_args, resolve_config
from experiments.common.environment import capture_environment
from experiments.common.io import create_run_directory, read_json, utc_timestamp, write_csv, write_json
from experiments.common.stats import PERFORMANCE_LATENCY_SUMMARY_SCHEMA, latency_summary_from_raw
from experiments.common.validation import (
    ADMISSION_MODES_SCHEMA,
    ADVERSARIAL_REJECTION_SCHEMA,
    FUNCTIONAL_CORRECTNESS_SCHEMA,
    PERFORMANCE_LATENCY_SCHEMA,
    REQUIRED_FIGURES,
    REQUIRED_SUMMARY_TABLES,
    STORAGE_SCALING_SCHEMA,
    validate_admission_matrix_present,
    validate_attack_cases_measured_or_unsupported,
    validate_csv_exact_schema,
    validate_depths_present,
    validate_final_artifacts,
    validate_non_empty_csv,
    validate_required_operations_present,
)


CLAIM_BOUNDARY = (
    "mock-anchored proof-of-descendancy experiment; no Bitcoin RPC, mining, "
    "mempool, transaction broadcast, block-header, or OP_RETURN latency measured"
)


def _write_validated_csv(path: Path, rows: list[dict[str, object]], schema: list[str]) -> None:
    write_csv(path, rows, schema)
    validate_csv_exact_schema(path, schema)
    validate_non_empty_csv(path)


def _run_functional(run_dir: Path, config: dict, environment: dict) -> Path:
    path = run_dir / "raw" / "functional_correctness.csv"
    rows = run_functional_correctness.build_rows(
        config=config,
        environment=environment,
        run_id=run_dir.name,
    )
    _write_validated_csv(path, rows, FUNCTIONAL_CORRECTNESS_SCHEMA)
    validate_depths_present(path, config["depths"])
    return path


def _run_adversarial(run_dir: Path, config: dict, environment: dict) -> Path:
    path = run_dir / "raw" / "adversarial_rejection.csv"
    rows = run_adversarial_rejection.build_rows(
        config=config,
        environment=environment,
        run_id=run_dir.name,
    )
    _write_validated_csv(path, rows, ADVERSARIAL_REJECTION_SCHEMA)
    validate_attack_cases_measured_or_unsupported(path, config["adversarial_attack_cases"])
    if not config["allow_exploratory_failures"]:
        failed = [
            str(row["trial_id"])
            for row in rows
            if row["supported"] is True
            and (row["false_accept"] is True or row["result"] in {"unexpected_status", "error"})
        ]
        if failed:
            raise RuntimeError("adversarial trial failures: " + "; ".join(failed[:5]))
    return path


def _run_storage(run_dir: Path, config: dict, environment: dict) -> Path:
    path = run_dir / "raw" / "storage_scaling.csv"
    rows = run_storage_scaling.build_rows(
        config=config,
        environment=environment,
        run_id=run_dir.name,
        artifacts_dir=run_dir / "raw" / "storage_scaling_artifacts",
    )
    _write_validated_csv(path, rows, STORAGE_SCALING_SCHEMA)
    validate_depths_present(path, config["depths"])
    return path


def _run_performance(run_dir: Path, config: dict, environment: dict) -> Path:
    path = run_dir / "raw" / "performance_latency.csv"
    rows, failures = run_performance_latency.build_rows(
        config=config,
        environment=environment,
        run_id=run_dir.name,
        cache_dir=run_dir / "raw" / "performance_latency_cache",
    )
    _write_validated_csv(path, rows, PERFORMANCE_LATENCY_SCHEMA)
    validate_required_operations_present(path, run_performance_latency.REQUIRED_OPERATIONS)

    summary_path = run_dir / "tables" / "performance_latency_summary.csv"
    _write_validated_csv(
        summary_path,
        latency_summary_from_raw(path),
        PERFORMANCE_LATENCY_SUMMARY_SCHEMA,
    )
    if failures and not config["allow_exploratory_failures"]:
        raise RuntimeError("performance latency trial failures: " + "; ".join(failures[:5]))
    return path


def _run_admission(run_dir: Path, config: dict, environment: dict) -> Path:
    run_admission_modes = importlib.import_module("experiments.run_admission_modes")
    path = run_dir / "raw" / "admission_modes.csv"
    rows = run_admission_modes.build_rows(
        config=config,
        environment=environment,
        run_id=run_dir.name,
    )
    _write_validated_csv(path, rows, ADMISSION_MODES_SCHEMA)
    validate_admission_matrix_present(path, config["admission_modes"], config["admission_peer_cases"])
    if not config["allow_exploratory_failures"]:
        failed = [
            str(row["trial_id"])
            for row in rows
            if row["result"] not in {"measured", "unsupported", "timeout"} or row["ok"] is False
        ]
        if failed:
            raise RuntimeError("admission mode trial failures: " + "; ".join(failed[:5]))
    return path


def _write_unsupported_admission(
    run_dir: Path,
    config: dict,
    environment: dict,
    *,
    reason: str,
) -> Path:
    rows: list[dict[str, object]] = []
    for mode in config["admission_modes"]:
        for peer_case in config["admission_peer_cases"]:
            rows.append({
                "schema_version": config["schema_version"],
                "run_id": run_dir.name,
                "runner": "admission_modes",
                "seed": config["seed"],
                "trial_id": f"admission-{mode}-{peer_case}-unsupported",
                "timestamp_utc": utc_timestamp(),
                "git_commit": environment["git_commit"],
                "python_version": environment["python_version"],
                "platform": environment["platform"],
                "mode": mode,
                "peer_case": peer_case,
                "lineage_enabled": mode != "disabled",
                "lineage_required": mode == "required",
                "proof_supplied": "",
                "proof_valid_expected": "",
                "join_accepted": "",
                "expected_join_accepted": "",
                "lineage_status_recorded": False,
                "lineage_ok": "",
                "lineage_status": "unsupported",
                "lineage_error_count": 0,
                "first_lineage_error": reason,
                "join_success_rate": "",
                "invalid_peer_rejection_rate": "",
                "duration_ms": "",
                "ok": True,
                "result": "unsupported",
                "error_message": reason,
            })
    path = run_dir / "raw" / "admission_modes.csv"
    _write_validated_csv(path, rows, ADMISSION_MODES_SCHEMA)
    validate_admission_matrix_present(path, config["admission_modes"], config["admission_peer_cases"])
    return path


def _record_stage(
    stages: dict[str, dict[str, object]],
    name: str,
    action: Callable[[], Path],
) -> Path:
    started = utc_timestamp()
    try:
        output = action()
    except Exception as exc:
        stages[name] = {
            "status": "failed",
            "started_at_utc": started,
            "finished_at_utc": utc_timestamp(),
            "error": str(exc),
        }
        raise
    stages[name] = {
        "status": "completed",
        "started_at_utc": started,
        "finished_at_utc": utc_timestamp(),
        "output": str(output),
    }
    return output


def _finalize_summary(
    run_dir: Path,
    *,
    stages: dict[str, dict[str, object]],
    smoke: bool,
    skip_admission: bool,
    continue_on_optional_failure: bool,
) -> Path:
    summary_path = run_dir / "summary.json"
    summary = read_json(summary_path)
    validation = summary.get("validation")
    if not isinstance(validation, dict):
        raise ValueError("summary.json validation must be an object")
    validation["smoke_tests_passed"] = True if smoke else "not_applicable"
    validation["unit_tests_passed"] = "not_run_by_pipeline"
    summary["orchestration"] = {
        "stages": stages,
        "skip_admission": skip_admission,
        "continue_on_optional_failure": continue_on_optional_failure,
    }
    write_json(summary_path, summary)
    validate_final_artifacts(
        run_dir,
        required_tables=REQUIRED_SUMMARY_TABLES,
        required_figures=REQUIRED_FIGURES,
    )
    return summary_path


def run(args: argparse.Namespace) -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    config = resolve_config(args.config, seed_override=args.seed, smoke=args.smoke)
    environment = capture_environment(repo_root)
    run_dir = create_run_directory(args.out, git_commit=str(environment["git_commit"]))
    config.update({
        "config_path": str(Path(args.config).resolve()),
        "run_id": run_dir.name,
        "claim_boundary": CLAIM_BOUNDARY,
        "orchestration": {
            "skip_admission": bool(args.skip_admission),
            "continue_on_optional_failure": bool(args.continue_on_optional_failure),
        },
    })
    write_json(run_dir / "config.json", config)
    write_json(run_dir / "environment.json", environment)

    stages: dict[str, dict[str, object]] = {}
    _record_stage(stages, "functional_correctness", lambda: _run_functional(run_dir, config, environment))
    _record_stage(stages, "adversarial_rejection", lambda: _run_adversarial(run_dir, config, environment))
    _record_stage(stages, "storage_scaling", lambda: _run_storage(run_dir, config, environment))
    _record_stage(stages, "performance_latency", lambda: _run_performance(run_dir, config, environment))

    if args.skip_admission:
        output = _write_unsupported_admission(
            run_dir,
            config,
            environment,
            reason="admission modes skipped by --skip-admission",
        )
        stages["admission_modes"] = {
            "status": "skipped",
            "finished_at_utc": utc_timestamp(),
            "output": str(output),
            "error": "",
        }
    else:
        started = utc_timestamp()
        try:
            output = _run_admission(run_dir, config, environment)
        except Exception as exc:
            if not args.continue_on_optional_failure:
                stages["admission_modes"] = {
                    "status": "failed",
                    "started_at_utc": started,
                    "finished_at_utc": utc_timestamp(),
                    "error": str(exc),
                }
                raise
            output = _write_unsupported_admission(
                run_dir,
                config,
                environment,
                reason=f"optional admission stage failed: {exc}",
            )
            stages["admission_modes"] = {
                "status": "failed_optional",
                "started_at_utc": started,
                "finished_at_utc": utc_timestamp(),
                "output": str(output),
                "error": str(exc),
            }
        else:
            stages["admission_modes"] = {
                "status": "completed",
                "started_at_utc": started,
                "finished_at_utc": utc_timestamp(),
                "output": str(output),
            }

    _record_stage(
        stages,
        "generate_plots_tables",
        lambda: generate_plots_tables.run(argparse.Namespace(run_dir=str(run_dir))),
    )
    _finalize_summary(
        run_dir,
        stages=stages,
        smoke=args.smoke,
        skip_admission=args.skip_admission,
        continue_on_optional_failure=args.continue_on_optional_failure,
    )
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument("--skip-admission", action="store_true", help="Record admission modes as unsupported.")
    parser.add_argument(
        "--continue-on-optional-failure",
        action="store_true",
        help="Continue after an admission-mode failure and record it as optional.",
    )
    args = parser.parse_args(argv)
    try:
        run_dir = run(args)
    except Exception as exc:
        print(f"complete experiment pipeline failed: {exc}", file=sys.stderr)
        return 1
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
