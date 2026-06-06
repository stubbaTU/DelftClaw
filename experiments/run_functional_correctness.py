"""Run mock-anchored lineage functional correctness trials."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from experiments.common.config import add_common_args, resolve_config
from experiments.common.environment import capture_environment
from experiments.common.fixtures import RUNNER_NAME, build_lineage_fixture
from experiments.common.io import create_run_directory, utc_timestamp, write_csv, write_json
from experiments.common.validation import (
    FUNCTIONAL_CORRECTNESS_SCHEMA,
    validate_csv_exact_schema,
    validate_depths_present,
    validate_non_empty_csv,
)
from identity.lineage.verifier import verify_lineage_proof


def _base_row(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    trial_id: str,
    timestamp_utc: str,
) -> dict[str, object]:
    return {
        "schema_version": config["schema_version"],
        "run_id": run_id,
        "runner": RUNNER_NAME,
        "seed": config["seed"],
        "trial_id": trial_id,
        "timestamp_utc": timestamp_utc,
        "git_commit": environment["git_commit"],
        "python_version": environment["python_version"],
        "platform": environment["platform"],
    }


def build_rows(*, config: dict, environment: dict, run_id: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    failures: list[str] = []
    for depth in config["depths"]:
        for trial_index in range(config["trials_per_depth"]):
            trial_id = f"functional-depth-{depth:02d}-trial-{trial_index:04d}"
            fixture = build_lineage_fixture(
                global_seed=config["seed"],
                depth=depth,
                trial_index=trial_index,
                requested_capability=config["requested_capability"],
                min_confirmations=config["min_confirmations"],
            )
            parsed_proof = fixture.proof.from_dict(fixture.proof.to_dict())
            verification = verify_lineage_proof(
                parsed_proof,
                trusted_roots=fixture.trusted_roots,
                requested_capability=config["requested_capability"],
                anchor_backend=fixture.anchor_backend,
                min_confirmations=config["min_confirmations"],
            )
            accepted = bool(verification.ok)
            first_error = verification.errors[0] if verification.errors else ""
            row = {
                **_base_row(
                    config=config,
                    environment=environment,
                    run_id=run_id,
                    trial_id=trial_id,
                    timestamp_utc=utc_timestamp(),
                ),
                "lineage_depth": depth,
                "certificate_count": 1 + len(parsed_proof.chain),
                "chain_certificate_count": len(parsed_proof.chain),
                "batch_size": len(fixture.batch.leaf_hashes),
                "merkle_proof_steps": len(parsed_proof.merkle_proof),
                "anchor_backend": parsed_proof.anchor_record.backend,
                "btc_network": parsed_proof.anchor_record.btc_network,
                "anchor_id": parsed_proof.anchor_id,
                "confirmations": verification.confirmations,
                "min_confirmations": config["min_confirmations"],
                "requested_capability": config["requested_capability"],
                "expected_accept": True,
                "accepted": accepted,
                "verification_status": verification.status,
                "verification_error_count": len(verification.errors),
                "first_verification_error": first_error,
                "valid_accept_rate": 1.0 if accepted else 0.0,
                "ok": accepted,
                "result": "accepted" if accepted else "rejected",
                "error_message": "" if accepted else first_error,
            }
            rows.append(row)
            if not accepted:
                failures.append(f"{trial_id}: {verification.status}: {first_error}")
    if failures:
        raise RuntimeError("valid mock-anchored proof rejected: " + "; ".join(failures[:5]))
    return rows


def run(args: argparse.Namespace) -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    config = resolve_config(args.config, seed_override=args.seed, smoke=args.smoke)
    environment = capture_environment(repo_root)
    run_dir = create_run_directory(args.out, git_commit=str(environment["git_commit"]))
    run_id = run_dir.name
    config["config_path"] = str(Path(args.config))
    config["run_id"] = run_id
    config["claim_boundary"] = "mock-anchored proof-of-descendancy experiment; no Bitcoin RPC/regtest anchoring"

    write_json(run_dir / "config.json", config)
    write_json(run_dir / "environment.json", environment)

    rows = build_rows(config=config, environment=environment, run_id=run_id)
    csv_path = run_dir / "raw" / "functional_correctness.csv"
    write_csv(csv_path, rows, FUNCTIONAL_CORRECTNESS_SCHEMA)
    validate_csv_exact_schema(csv_path, FUNCTIONAL_CORRECTNESS_SCHEMA)
    validate_non_empty_csv(csv_path)
    validate_depths_present(csv_path, config["depths"])
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        print(f"functional correctness runner failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
