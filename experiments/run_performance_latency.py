"""Run mock-anchored lineage performance latency benchmarks."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Callable

from experiments.common.config import add_common_args, resolve_config
from experiments.common.environment import capture_environment
from experiments.common.fixtures import (
    FIXED_EXPIRES_AT,
    FIXED_ISSUED_AT,
    build_lineage_fixture,
    deterministic_private_key,
    public_key_hex,
)
from experiments.common.io import create_run_directory, utc_timestamp, write_csv, write_json
from experiments.common.stats import PERFORMANCE_LATENCY_SUMMARY_SCHEMA, latency_summary_from_raw
from experiments.common.timing import Timer, measure
from experiments.common.validation import (
    PERFORMANCE_LATENCY_SCHEMA,
    validate_csv_exact_schema,
    validate_non_empty_csv,
    validate_required_operations_present,
    validate_summary_matches_raw,
)
from identity.lineage.certificates import issue_child_certificate, verify_certificate_id, verify_certificate_signature
from identity.lineage.merkle import merkle_proof, merkle_root, verify_merkle_proof
from identity.lineage.mock_anchor import MockAnchorBackend
from identity.lineage.models import CertificateBatch, ChildCertificateV1, VerificationResult
from identity.lineage.verifier import verify_lineage_proof


RUNNER_NAME = "performance_latency"
REQUIRED_OPERATIONS = [
    "certificate_issue",
    "merkle_root_build",
    "merkle_proof_build",
    "mock_anchor_create",
    "verify_cold",
    "verify_cached",
]


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


def _row(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    trial_id: str,
    operation: str,
    lineage_depth: int | str,
    batch_size: int | str,
    cache_mode: str,
    warmup: bool,
    timed_section: str,
    duration_ms: float | str,
    verification_status: str,
    certificate_count: int | str,
    merkle_proof_steps: int | str,
    ok: bool,
    result: str,
    error_message: str = "",
) -> dict[str, object]:
    return {
        **_base_row(
            config=config,
            environment=environment,
            run_id=run_id,
            trial_id=trial_id,
            timestamp_utc=utc_timestamp(),
        ),
        "operation": operation,
        "lineage_depth": lineage_depth,
        "batch_size": batch_size,
        "cache_mode": cache_mode,
        "warmup": warmup,
        "timed_section": timed_section,
        "duration_ms": duration_ms,
        "verification_status": verification_status,
        "certificate_count": certificate_count,
        "merkle_proof_steps": merkle_proof_steps,
        "anchor_backend": config["anchor_backend"],
        "btc_network": config["btc_network"],
        "ok": ok,
        "result": result,
        "error_message": error_message,
    }


def _iterations(config: dict) -> list[tuple[bool, int]]:
    warmups = [(True, index) for index in range(int(config["performance_warmup_iterations"]))]
    trials = [(False, index) for index in range(int(config["performance_measured_trials"]))]
    return [*warmups, *trials]


def _leaf_hashes(*, seed: int, operation: str, batch_size: int, trial_id: str) -> list[str]:
    return [
        hashlib.sha256(f"{seed}|{operation}|{batch_size}|{trial_id}|leaf|{index}".encode("utf-8")).hexdigest()
        for index in range(batch_size)
    ]


def _certificate_inputs(*, seed: int, depth: int, trial_id: str, requested_capability: str) -> dict[str, object]:
    prefix = f"{seed}|{RUNNER_NAME}|certificate_issue|{depth}|{trial_id}"
    parent_key = deterministic_private_key(f"{prefix}|parent-key")
    child_key = deterministic_private_key(f"{prefix}|child-key")
    return {
        "parent_signing_key": parent_key,
        "family_id": f"mock-perf-family-{hashlib.sha256(f'{prefix}|family'.encode('utf-8')).hexdigest()[:12]}",
        "parent_agent_id": f"agent-parent-{depth:02d}",
        "parent_authority_pubkey": public_key_hex(parent_key),
        "child_agent_id": f"agent-child-{hashlib.sha256(f'{prefix}|child'.encode('utf-8')).hexdigest()[:12]}",
        "child_authority_pubkey": public_key_hex(child_key),
        "child_operational_pubkey": hashlib.sha256(f"{prefix}|operational".encode("utf-8")).hexdigest(),
        "issued_at": FIXED_ISSUED_AT,
        "expires_at": FIXED_EXPIRES_AT,
        "capabilities": [requested_capability],
        "constraints": {"lineage_depth": depth, "experiment": RUNNER_NAME},
        "anchor_policy": {"required": True, "min_confirmations": 0},
    }


def _batch_for_leaves(*, batch_size: int, leaves: list[str], root: str, trial_id: str) -> CertificateBatch:
    return CertificateBatch(
        batch_id=hashlib.sha256(f"{RUNNER_NAME}|batch|{batch_size}|{trial_id}".encode("utf-8")).hexdigest(),
        merkle_root=root,
        leaf_hashes=leaves,
        certificate_ids=[f"mock-certificate-{index:04d}" for index in range(batch_size)],
        created_at=FIXED_ISSUED_AT,
    )


def _measure_trial(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    trial_id: str,
    operation: str,
    lineage_depth: int | str,
    batch_size: int | str,
    cache_mode: str,
    warmup: bool,
    timed_section: str,
    certificate_count: int | str,
    merkle_proof_steps: Callable[[object], int | str] | int | str,
    action: Callable[[], object],
    validate: Callable[[object], str],
) -> tuple[dict[str, object], str | None]:
    timer = Timer()
    try:
        with measure() as active_timer:
            timer = active_timer
            measured = action()
        verification_status = validate(measured)
        steps = merkle_proof_steps(measured) if callable(merkle_proof_steps) else merkle_proof_steps
        return (
            _row(
                config=config,
                environment=environment,
                run_id=run_id,
                trial_id=trial_id,
                operation=operation,
                lineage_depth=lineage_depth,
                batch_size=batch_size,
                cache_mode=cache_mode,
                warmup=warmup,
                timed_section=timed_section,
                duration_ms=timer.duration_ms,
                verification_status=verification_status,
                certificate_count=certificate_count,
                merkle_proof_steps=steps,
                ok=True,
                result="measured",
            ),
            None,
        )
    except Exception as exc:
        return (
            _row(
                config=config,
                environment=environment,
                run_id=run_id,
                trial_id=trial_id,
                operation=operation,
                lineage_depth=lineage_depth,
                batch_size=batch_size,
                cache_mode=cache_mode,
                warmup=warmup,
                timed_section=timed_section,
                duration_ms=timer.duration_ms if timer.end_ns else "",
                verification_status="error",
                certificate_count=certificate_count,
                merkle_proof_steps="",
                ok=False,
                result="error",
                error_message=str(exc),
            ),
            f"{trial_id}: {exc}",
        )


def _validate_certificate(certificate: object) -> str:
    if not isinstance(certificate, ChildCertificateV1):
        raise TypeError("certificate_issue did not return a child certificate")
    if not verify_certificate_id(certificate):
        raise RuntimeError("issued certificate id is invalid")
    if not verify_certificate_signature(certificate):
        raise RuntimeError("issued certificate signature is invalid")
    return "valid"


def _validate_merkle_root(root: object) -> str:
    if not isinstance(root, str) or len(root) != 64:
        raise RuntimeError("Merkle root was not a 32-byte hex digest")
    return "valid"


def _validate_verification(result: object) -> str:
    if not isinstance(result, VerificationResult):
        raise TypeError("verification did not return a VerificationResult")
    if not result.ok:
        first_error = result.errors[0] if result.errors else result.status
        raise RuntimeError(f"verification failed: {result.status}: {first_error}")
    return result.status


def _add_certificate_issue_rows(
    *,
    rows: list[dict[str, object]],
    failures: list[str],
    config: dict,
    environment: dict,
    run_id: str,
) -> None:
    for depth in config["performance_depths"]:
        for warmup, index in _iterations(config):
            phase = "warmup" if warmup else "trial"
            trial_id = f"performance-certificate_issue-depth-{depth:02d}-{phase}-{index:04d}"
            inputs = _certificate_inputs(
                seed=config["seed"],
                depth=depth,
                trial_id=trial_id,
                requested_capability=config["requested_capability"],
            )
            row, failure = _measure_trial(
                config=config,
                environment=environment,
                run_id=run_id,
                trial_id=trial_id,
                operation="certificate_issue",
                lineage_depth=depth,
                batch_size="",
                cache_mode="none",
                warmup=warmup,
                timed_section="issue_child_certificate",
                certificate_count=1,
                merkle_proof_steps=0,
                action=lambda inputs=inputs: issue_child_certificate(**inputs),
                validate=_validate_certificate,
            )
            rows.append(row)
            if failure:
                failures.append(failure)


def _add_merkle_rows(
    *,
    rows: list[dict[str, object]],
    failures: list[str],
    config: dict,
    environment: dict,
    run_id: str,
) -> None:
    for batch_size in config["performance_batch_sizes"]:
        for warmup, index in _iterations(config):
            phase = "warmup" if warmup else "trial"
            trial_id = f"performance-merkle_root_build-batch-{batch_size:04d}-{phase}-{index:04d}"
            leaves = _leaf_hashes(
                seed=config["seed"],
                operation="merkle_root_build",
                batch_size=batch_size,
                trial_id=trial_id,
            )
            row, failure = _measure_trial(
                config=config,
                environment=environment,
                run_id=run_id,
                trial_id=trial_id,
                operation="merkle_root_build",
                lineage_depth="",
                batch_size=batch_size,
                cache_mode="none",
                warmup=warmup,
                timed_section="merkle_root",
                certificate_count=0,
                merkle_proof_steps=0,
                action=lambda leaves=leaves: merkle_root(leaves),
                validate=_validate_merkle_root,
            )
            rows.append(row)
            if failure:
                failures.append(failure)

            trial_id = f"performance-merkle_proof_build-batch-{batch_size:04d}-{phase}-{index:04d}"
            leaves = _leaf_hashes(
                seed=config["seed"],
                operation="merkle_proof_build",
                batch_size=batch_size,
                trial_id=trial_id,
            )
            root = merkle_root(leaves)
            leaf_index = batch_size // 2

            def validate_proof(proof: object, *, leaves: list[str] = leaves, root: str = root, leaf_index: int = leaf_index) -> str:
                if not isinstance(proof, list):
                    raise TypeError("merkle_proof did not return a list")
                if not verify_merkle_proof(
                    leaf_hash=leaves[leaf_index],
                    proof=proof,
                    expected_root=root,
                ):
                    raise RuntimeError("Merkle proof did not verify")
                return "valid"

            row, failure = _measure_trial(
                config=config,
                environment=environment,
                run_id=run_id,
                trial_id=trial_id,
                operation="merkle_proof_build",
                lineage_depth="",
                batch_size=batch_size,
                cache_mode="none",
                warmup=warmup,
                timed_section="merkle_proof",
                certificate_count=0,
                merkle_proof_steps=lambda proof: len(proof) if isinstance(proof, list) else "",
                action=lambda leaves=leaves, leaf_index=leaf_index: merkle_proof(leaves, leaf_index),
                validate=validate_proof,
            )
            rows.append(row)
            if failure:
                failures.append(failure)


def _add_anchor_rows(
    *,
    rows: list[dict[str, object]],
    failures: list[str],
    config: dict,
    environment: dict,
    run_id: str,
) -> None:
    for batch_size in config["performance_batch_sizes"]:
        for warmup, index in _iterations(config):
            phase = "warmup" if warmup else "trial"
            trial_id = f"performance-mock_anchor_create-batch-{batch_size:04d}-{phase}-{index:04d}"
            leaves = _leaf_hashes(
                seed=config["seed"],
                operation="mock_anchor_create",
                batch_size=batch_size,
                trial_id=trial_id,
            )
            root = merkle_root(leaves)
            batch = _batch_for_leaves(batch_size=batch_size, leaves=leaves, root=root, trial_id=trial_id)
            backend = MockAnchorBackend(confirmations=max(config["min_confirmations"], 1))

            def validate_anchor(anchor: object, *, backend: MockAnchorBackend = backend, root: str = root) -> str:
                result = backend.verify_anchor(anchor, root, config["min_confirmations"])
                if not result.ok:
                    first_error = result.errors[0] if result.errors else result.status
                    raise RuntimeError(f"mock anchor verification failed: {result.status}: {first_error}")
                return result.status

            row, failure = _measure_trial(
                config=config,
                environment=environment,
                run_id=run_id,
                trial_id=trial_id,
                operation="mock_anchor_create",
                lineage_depth="",
                batch_size=batch_size,
                cache_mode="none",
                warmup=warmup,
                timed_section="MockAnchorBackend.create_anchor",
                certificate_count=0,
                merkle_proof_steps=0,
                action=lambda backend=backend, batch=batch: backend.create_anchor(batch),
                validate=validate_anchor,
            )
            rows.append(row)
            if failure:
                failures.append(failure)


def _add_verify_rows(
    *,
    rows: list[dict[str, object]],
    failures: list[str],
    config: dict,
    environment: dict,
    run_id: str,
    cache_dir: Path,
) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    for depth in config["performance_depths"]:
        for warmup, index in _iterations(config):
            phase = "warmup" if warmup else "trial"
            trial_id = f"performance-verify_cold-depth-{depth:02d}-{phase}-{index:04d}"
            fixture = build_lineage_fixture(
                global_seed=config["seed"],
                depth=depth,
                trial_index=index,
                requested_capability=config["requested_capability"],
                min_confirmations=config["min_confirmations"],
                runner=RUNNER_NAME,
            )
            proof = fixture.proof
            row, failure = _measure_trial(
                config=config,
                environment=environment,
                run_id=run_id,
                trial_id=trial_id,
                operation="verify_cold",
                lineage_depth=depth,
                batch_size=len(fixture.batch.leaf_hashes),
                cache_mode="cold",
                warmup=warmup,
                timed_section="verify_lineage_proof",
                certificate_count=1 + len(proof.chain),
                merkle_proof_steps=len(proof.merkle_proof),
                action=lambda fixture=fixture, proof=proof: verify_lineage_proof(
                    proof,
                    trusted_roots=fixture.trusted_roots,
                    requested_capability=config["requested_capability"],
                    anchor_backend=fixture.anchor_backend,
                    min_confirmations=config["min_confirmations"],
                    cache=None,
                ),
                validate=_validate_verification,
            )
            rows.append(row)
            if failure:
                failures.append(failure)

            trial_id = f"performance-verify_cached-depth-{depth:02d}-{phase}-{index:04d}"
            fixture = build_lineage_fixture(
                global_seed=config["seed"],
                depth=depth,
                trial_index=index,
                requested_capability=config["requested_capability"],
                min_confirmations=config["min_confirmations"],
                runner=RUNNER_NAME,
            )
            proof = fixture.proof
            cache_path = cache_dir / f"{trial_id}.json"
            try:
                populated = verify_lineage_proof(
                    proof,
                    trusted_roots=fixture.trusted_roots,
                    requested_capability=config["requested_capability"],
                    anchor_backend=fixture.anchor_backend,
                    min_confirmations=config["min_confirmations"],
                    cache=cache_path,
                )
                _validate_verification(populated)
            except Exception as exc:
                row = _row(
                    config=config,
                    environment=environment,
                    run_id=run_id,
                    trial_id=trial_id,
                    operation="verify_cached",
                    lineage_depth=depth,
                    batch_size=len(fixture.batch.leaf_hashes),
                    cache_mode="cached",
                    warmup=warmup,
                    timed_section="verify_lineage_proof",
                    duration_ms="",
                    verification_status="error",
                    certificate_count=1 + len(proof.chain),
                    merkle_proof_steps=len(proof.merkle_proof),
                    ok=False,
                    result="error",
                    error_message=f"cache population failed: {exc}",
                )
                rows.append(row)
                failures.append(f"{trial_id}: cache population failed: {exc}")
                continue

            row, failure = _measure_trial(
                config=config,
                environment=environment,
                run_id=run_id,
                trial_id=trial_id,
                operation="verify_cached",
                lineage_depth=depth,
                batch_size=len(fixture.batch.leaf_hashes),
                cache_mode="cached",
                warmup=warmup,
                timed_section="verify_lineage_proof",
                certificate_count=1 + len(proof.chain),
                merkle_proof_steps=len(proof.merkle_proof),
                action=lambda fixture=fixture, proof=proof, cache_path=cache_path: verify_lineage_proof(
                    proof,
                    trusted_roots=fixture.trusted_roots,
                    requested_capability=config["requested_capability"],
                    anchor_backend=fixture.anchor_backend,
                    min_confirmations=config["min_confirmations"],
                    cache=cache_path,
                ),
                validate=_validate_verification,
            )
            rows.append(row)
            if failure:
                failures.append(failure)


def build_rows(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    cache_dir: Path,
) -> tuple[list[dict[str, object]], list[str]]:
    rows: list[dict[str, object]] = []
    failures: list[str] = []
    _add_certificate_issue_rows(rows=rows, failures=failures, config=config, environment=environment, run_id=run_id)
    _add_merkle_rows(rows=rows, failures=failures, config=config, environment=environment, run_id=run_id)
    _add_anchor_rows(rows=rows, failures=failures, config=config, environment=environment, run_id=run_id)
    _add_verify_rows(
        rows=rows,
        failures=failures,
        config=config,
        environment=environment,
        run_id=run_id,
        cache_dir=cache_dir,
    )
    return rows, failures


def run(args: argparse.Namespace) -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    config = resolve_config(args.config, seed_override=args.seed, smoke=args.smoke)
    environment = capture_environment(repo_root)
    run_dir = create_run_directory(args.out, git_commit=str(environment["git_commit"]))
    run_id = run_dir.name
    config["config_path"] = str(Path(args.config))
    config["run_id"] = run_id
    config["claim_boundary"] = (
        "mock-anchored local protocol overhead only; no Bitcoin RPC, mining, mempool, "
        "transaction broadcast, block header, or OP_RETURN latency measured"
    )

    write_json(run_dir / "config.json", config)
    write_json(run_dir / "environment.json", environment)

    rows, failures = build_rows(
        config=config,
        environment=environment,
        run_id=run_id,
        cache_dir=run_dir / "raw" / "performance_latency_cache",
    )
    csv_path = run_dir / "raw" / "performance_latency.csv"
    write_csv(csv_path, rows, PERFORMANCE_LATENCY_SCHEMA)
    validate_csv_exact_schema(csv_path, PERFORMANCE_LATENCY_SCHEMA)
    validate_non_empty_csv(csv_path)
    validate_required_operations_present(csv_path, REQUIRED_OPERATIONS)

    summary_path = run_dir / "tables" / "performance_latency_summary.csv"
    write_csv(summary_path, latency_summary_from_raw(csv_path), PERFORMANCE_LATENCY_SUMMARY_SCHEMA)
    validate_csv_exact_schema(summary_path, PERFORMANCE_LATENCY_SUMMARY_SCHEMA)
    validate_non_empty_csv(summary_path)
    validate_summary_matches_raw(csv_path, summary_path)

    if failures and not config["allow_exploratory_failures"]:
        raise RuntimeError("performance latency trial failures: " + "; ".join(failures[:5]))
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        print(f"performance latency runner failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
