"""Rebuild OpenClaw LLM CSV outputs from finalized per-trial artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from deploy.openclaw_output import parse_openclaw_json_stdout
from experiments.common.io import read_json, write_csv
from experiments.common.validation import (
    OPENCLAW_LLM_ADVERSARIAL_SCHEMA,
    OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA,
    validate_csv_exact_schema,
    validate_non_empty_csv,
)


RUNNER_NAME = "openclaw_llm_adversarial"
TRIAL_ID_PATTERN = re.compile(
    r"^openclaw-llm-(disabled|optional|required)-(.+)-trial-(\d{4})$"
)
REQUIRED_ARTIFACTS = (
    "prompt.txt",
    "openclaw_stdout.json",
    "openclaw_stderr.txt",
    "tool_calls.jsonl",
    "protocol_result.json",
    "metadata.json",
    "artifact_manifest.json",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _tool_success(rows: list[dict[str, Any]], name: str) -> bool:
    return any(row.get("tool") == name and row.get("ok") is True for row in rows)


def _summary_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["lineage_mode"]), str(row["attack_case"]))].append(row)

    output = []
    for (mode, attack_case), group in sorted(grouped.items()):
        trials = len(group)
        llm_successes = sum(row["llm_task_success"] is True for row in group)
        join_rows = [row for row in group if row["join_attempted"] is True]
        protocol_successes = sum(
            row["protocol_expectation_met"] is True for row in join_rows
        )
        output.append({
            "lineage_mode": mode,
            "attack_case": attack_case,
            "trials": trials,
            "llm_task_successes": llm_successes,
            "llm_task_success_rate": llm_successes / trials if trials else 0.0,
            "join_attempts": len(join_rows),
            "protocol_expectation_met_count": protocol_successes,
            "protocol_correct_rate": (
                protocol_successes / len(join_rows) if join_rows else ""
            ),
            "false_accepts": sum(row["false_accept"] is True for row in join_rows),
        })
    return output


def _relative(path: Path, run_dir: Path) -> str:
    return path.relative_to(run_dir).as_posix()


def _artifact_timestamp(path: Path) -> str:
    return datetime.fromtimestamp(
        path.stat().st_mtime,
        tz=timezone.utc,
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_recovered_row(
    artifact_dir: Path,
    *,
    run_dir: Path,
    config: dict[str, Any],
    environment: dict[str, Any],
    preflight: dict[str, Any],
) -> dict[str, object]:
    match = TRIAL_ID_PATTERN.fullmatch(artifact_dir.name)
    if match is None:
        raise ValueError(f"unrecognized trial directory: {artifact_dir.name}")
    mode, attack_case, trial_index_text = match.groups()
    trial_index = int(trial_index_text)

    paths = {name: artifact_dir / name for name in REQUIRED_ARTIFACTS}
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        raise ValueError(f"incomplete artifacts ({', '.join(missing)})")

    metadata = read_json(paths["metadata.json"])
    protocol = read_json(paths["protocol_result.json"])
    ledger_rows = _read_ledger(paths["tool_calls.jsonl"])
    stdout = paths["openclaw_stdout.json"].read_text(encoding="utf-8")
    summary = parse_openclaw_json_stdout(stdout)
    semantic_error = summary.semantic_error or summary.parse_error or ""

    prepare_called = _tool_success(
        ledger_rows,
        "lineage_experiment_prepare_case",
    )
    request_called = _tool_success(
        ledger_rows,
        "lineage_experiment_request_join",
    )
    status_called = _tool_success(
        ledger_rows,
        "lineage_experiment_peer_status",
    )
    expected_tools_called = prepare_called and request_called and status_called
    llm_task_success = bool(
        expected_tools_called and protocol["join_attempted"]
    )
    protocol_assessed_ok = bool(
        not protocol["join_attempted"] or protocol["protocol_expectation_met"]
    )
    row_ok = bool(not semantic_error and protocol_assessed_ok)
    if semantic_error:
        result_name = "runner_error"
        error_message = semantic_error
    elif not llm_task_success:
        result_name = "llm_task_failure"
        error_message = ""
    elif not protocol["protocol_expectation_met"]:
        result_name = "protocol_mismatch"
        error_message = "protocol_expectation_mismatch"
    else:
        result_name = "measured"
        error_message = ""

    timing_seconds = metadata.get("timing_seconds", {})
    duration_ms = sum(float(value) for value in timing_seconds.values()) * 1000
    lineage_errors = protocol["lineage_errors"]
    model_seed = metadata.get("model_seed")
    if model_seed is None:
        model_seed = int.from_bytes(
            hashlib.sha256(
                f"{config['seed']}|{artifact_dir.name}".encode("utf-8")
            ).digest()[:4],
            "big",
        )

    return {
        "schema_version": config["schema_version"],
        "run_id": run_dir.name,
        "runner": RUNNER_NAME,
        "seed": config["seed"],
        "trial_id": artifact_dir.name,
        "timestamp_utc": _artifact_timestamp(paths["metadata.json"]),
        "git_commit": environment["git_commit"],
        "python_version": environment["python_version"],
        "platform": environment["platform"],
        "attack_case": attack_case,
        "selected_attack_case": protocol["selected_attack_case"],
        "lineage_mode": mode,
        "provider": metadata["provider"],
        "model": metadata["model"],
        "model_ref": metadata["model_ref"],
        "openclaw_version": metadata.get(
            "openclaw_version",
            preflight["openclaw"]["openclaw_version"],
        ),
        "openclaw_agent_id": metadata["agent_id"],
        "prompt_hash": sha256_file(paths["prompt.txt"]),
        "trial_attempt": trial_index,
        "temperature": metadata["temperature"],
        "model_seed": model_seed,
        "max_tokens": metadata["max_tokens"],
        "tool_loop_started": bool(ledger_rows),
        "tool_calls_count": len(ledger_rows),
        "prepare_called": prepare_called,
        "expected_tool_called": expected_tools_called,
        "join_attempted": protocol["join_attempted"],
        "status_called": status_called,
        "proof_supplied": protocol["proof_supplied"],
        "expected_accept": protocol["expected_accept"],
        "join_accepted": (
            protocol["join_accepted"]
            if protocol["join_accepted"] is not None
            else ""
        ),
        "lineage_status": protocol["lineage_status"],
        "rejected": protocol["rejected"],
        "false_accept": protocol["false_accept"],
        "llm_task_success": llm_task_success,
        "protocol_expectation_met": protocol["protocol_expectation_met"],
        "duration_ms": duration_ms,
        "openclaw_exit_code": 0 if not semantic_error else -1,
        "openclaw_semantic_error": semantic_error,
        "lineage_error_count": len(lineage_errors),
        "first_lineage_error": str(lineage_errors[0]) if lineage_errors else "",
        "stdout_artifact": _relative(paths["openclaw_stdout.json"], run_dir),
        "stdout_sha256": sha256_file(paths["openclaw_stdout.json"]),
        "stderr_artifact": _relative(paths["openclaw_stderr.txt"], run_dir),
        "stderr_sha256": sha256_file(paths["openclaw_stderr.txt"]),
        "tool_ledger_artifact": _relative(paths["tool_calls.jsonl"], run_dir),
        "tool_ledger_sha256": sha256_file(paths["tool_calls.jsonl"]),
        "protocol_artifact": _relative(paths["protocol_result.json"], run_dir),
        "protocol_sha256": sha256_file(paths["protocol_result.json"]),
        "artifact_manifest": _relative(paths["artifact_manifest.json"], run_dir),
        "artifact_manifest_sha256": sha256_file(paths["artifact_manifest.json"]),
        "ok": row_ok,
        "result": result_name,
        "error_message": error_message,
    }


def recover_run(run_dir: str | Path, *, force: bool = False) -> tuple[Path, Path]:
    root = Path(run_dir).resolve()
    config = read_json(root / "config.json")
    environment = read_json(root / "environment.json")
    preflight = read_json(root / "preflight.json")
    artifact_root = root / "raw" / RUNNER_NAME
    if not artifact_root.is_dir():
        raise ValueError(f"trial artifact directory does not exist: {artifact_root}")

    raw_path = root / "raw" / "openclaw_llm_adversarial.csv"
    summary_path = root / "tables" / "openclaw_llm_adversarial_summary.csv"
    existing = [path for path in (raw_path, summary_path) if path.exists()]
    if existing and not force:
        raise FileExistsError(
            "refusing to overwrite existing output; pass --force to replace it"
        )

    rows = []
    skipped = []
    for artifact_dir in sorted(path for path in artifact_root.iterdir() if path.is_dir()):
        try:
            rows.append(_load_recovered_row(
                artifact_dir,
                run_dir=root,
                config=config,
                environment=environment,
                preflight=preflight,
            ))
        except ValueError as exc:
            skipped.append(f"{artifact_dir.name}: {exc}")
    if not rows:
        raise ValueError("no finalized trial artifacts were found")

    write_csv(raw_path, rows, OPENCLAW_LLM_ADVERSARIAL_SCHEMA)
    write_csv(
        summary_path,
        _summary_rows(rows),
        OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA,
    )
    validate_csv_exact_schema(raw_path, OPENCLAW_LLM_ADVERSARIAL_SCHEMA)
    validate_non_empty_csv(raw_path)
    validate_csv_exact_schema(
        summary_path,
        OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA,
    )
    print(f"Recovered {len(rows)} finalized trials.")
    for message in skipped:
        print(f"Skipped {message}")
    return raw_path, summary_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", help="Interrupted OpenClaw LLM run directory.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace CSV outputs if they already exist.",
    )
    args = parser.parse_args(argv)
    raw_path, summary_path = recover_run(args.run_dir, force=args.force)
    print(raw_path)
    print(summary_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
