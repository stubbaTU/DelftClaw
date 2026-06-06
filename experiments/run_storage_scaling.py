"""Run storage scaling trials for mock-anchored lineage proofs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from experiments.common.config import add_common_args, resolve_config
from experiments.common.environment import capture_environment
from experiments.common.fixtures import build_lineage_fixture
from experiments.common.io import (
    create_run_directory,
    directory_total_bytes,
    file_size_bytes,
    utc_timestamp,
    write_csv,
    write_json,
)
from experiments.common.validation import (
    STORAGE_SCALING_SCHEMA,
    validate_csv_exact_schema,
    validate_depths_present,
    validate_non_empty_csv,
)
from identity.lineage.canonical import canonical_json_bytes
from identity.lineage.store import LineageStore
from identity.lineage.verifier import verify_lineage_proof


RUNNER_NAME = "storage_scaling"


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


def _birth_package(fixture) -> dict[str, object]:
    proof = fixture.proof
    return {
        "version": 1,
        "package_type": "lineage_birth_package_v1",
        "proof": proof.to_dict(),
        "certificate_id": proof.leaf_certificate.certificate_id,
        "trusted_roots": fixture.trusted_roots,
        "revocation_feed": [event.to_dict() if hasattr(event, "to_dict") else dict(event) for event in proof.revocation_events],
    }


def _persist_fixture(fixture, save_dir: Path, *, requested_capability: str, min_confirmations: int) -> dict[str, int]:
    proof = fixture.proof
    store = LineageStore(save_dir)

    store.save_birth_package(_birth_package(fixture))
    for certificate in [*reversed(proof.chain), proof.leaf_certificate]:
        store.append_certificate(certificate)
    store.append_anchor(proof.anchor_record)
    for event in proof.revocation_events:
        store.append_revocation(event)
    batch_path = store.save_batch(fixture.batch)

    verification = verify_lineage_proof(
        proof,
        trusted_roots=fixture.trusted_roots,
        requested_capability=requested_capability,
        anchor_backend=fixture.anchor_backend,
        min_confirmations=min_confirmations,
        cache=store.cache_path,
    )
    if not verification.ok:
        first_error = verification.errors[0] if verification.errors else verification.status
        raise RuntimeError(f"stored proof did not verify: {verification.status}: {first_error}")

    required_paths = {
        "birth package": store.birth_package_path,
        "certificate log": store.certificates_path,
        "anchor log": store.anchors_path,
        "batch file": batch_path,
    }
    missing = [name for name, path in required_paths.items() if not path.exists()]
    if missing:
        raise RuntimeError("required lineage store artifact missing: " + ", ".join(missing))

    return {
        "birth_package_bytes": file_size_bytes(store.birth_package_path),
        "certificate_log_bytes": file_size_bytes(store.certificates_path),
        "anchor_log_bytes": file_size_bytes(store.anchors_path),
        "revocation_log_bytes": file_size_bytes(store.revocations_path),
        "cache_bytes": file_size_bytes(store.cache_path),
        "batch_file_bytes": file_size_bytes(batch_path),
        "lineage_dir_total_bytes": directory_total_bytes(store.root),
    }


def _error_row(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    trial_id: str,
    lineage_depth: int,
    error_message: str,
) -> dict[str, object]:
    return {
        **_base_row(
            config=config,
            environment=environment,
            run_id=run_id,
            trial_id=trial_id,
            timestamp_utc=utc_timestamp(),
        ),
        "lineage_depth": lineage_depth,
        "certificate_count": 0,
        "chain_certificate_count": 0,
        "batch_size": 0,
        "merkle_proof_steps": 0,
        "proof_json_bytes": 0,
        "birth_package_bytes": 0,
        "certificate_log_bytes": 0,
        "anchor_log_bytes": 0,
        "revocation_log_bytes": 0,
        "cache_bytes": 0,
        "batch_file_bytes": 0,
        "lineage_dir_total_bytes": 0,
        "ok": False,
        "result": "error",
        "error_message": error_message,
    }


def build_rows(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    artifacts_dir: Path,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    failures: list[str] = []
    trials_per_depth = int(config["storage_trials_per_depth"])

    for depth in config["depths"]:
        for trial_index in range(trials_per_depth):
            trial_id = f"storage-depth-{depth:02d}-trial-{trial_index:04d}"
            try:
                fixture = build_lineage_fixture(
                    global_seed=config["seed"],
                    depth=depth,
                    trial_index=trial_index,
                    requested_capability=config["requested_capability"],
                    min_confirmations=config["min_confirmations"],
                    runner=RUNNER_NAME,
                )
                parsed_proof = fixture.proof.from_dict(fixture.proof.to_dict())
                verification = verify_lineage_proof(
                    parsed_proof,
                    trusted_roots=fixture.trusted_roots,
                    requested_capability=config["requested_capability"],
                    anchor_backend=fixture.anchor_backend,
                    min_confirmations=config["min_confirmations"],
                )
                if not verification.ok:
                    first_error = verification.errors[0] if verification.errors else verification.status
                    raise RuntimeError(f"valid proof rejected: {verification.status}: {first_error}")

                sizes = _persist_fixture(
                    fixture,
                    artifacts_dir / trial_id,
                    requested_capability=config["requested_capability"],
                    min_confirmations=config["min_confirmations"],
                )
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
                    "proof_json_bytes": len(canonical_json_bytes(parsed_proof.to_dict())),
                    **sizes,
                    "ok": True,
                    "result": "measured",
                    "error_message": "",
                }
                rows.append(row)
            except Exception as exc:
                rows.append(_error_row(
                    config=config,
                    environment=environment,
                    run_id=run_id,
                    trial_id=trial_id,
                    lineage_depth=depth,
                    error_message=str(exc),
                ))
                failures.append(f"{trial_id}: {exc}")

    if failures:
        raise RuntimeError("storage scaling trial failures: " + "; ".join(failures[:5]))
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

    rows = build_rows(
        config=config,
        environment=environment,
        run_id=run_id,
        artifacts_dir=run_dir / "raw" / "storage_scaling_artifacts",
    )
    csv_path = run_dir / "raw" / "storage_scaling.csv"
    write_csv(csv_path, rows, STORAGE_SCALING_SCHEMA)
    validate_csv_exact_schema(csv_path, STORAGE_SCALING_SCHEMA)
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
        print(f"storage scaling runner failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
