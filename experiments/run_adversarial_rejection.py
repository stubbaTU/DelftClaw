"""Run adversarial rejection trials for mock-anchored lineage proofs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from experiments.common.config import add_common_args, resolve_config
from experiments.common.environment import capture_environment
from experiments.common.fixtures import build_lineage_fixture
from experiments.common.io import create_run_directory, utc_timestamp, write_csv, write_json
from experiments.common.mutations import RUNNER_NAME, mutate_fixture, unsupported_case
from experiments.common.validation import (
    ADVERSARIAL_REJECTION_SCHEMA,
    validate_attack_cases_measured_or_unsupported,
    validate_csv_exact_schema,
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


def _unsupported_row(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    attack_case: str,
    trial_id: str,
    lineage_depth: int,
    error_message: str,
) -> dict[str, object]:
    mutation = unsupported_case(attack_case, error_message)
    return {
        **_base_row(
            config=config,
            environment=environment,
            run_id=run_id,
            trial_id=trial_id,
            timestamp_utc=utc_timestamp(),
        ),
        "attack_case": attack_case,
        "mutation_target": mutation.mutation_target,
        "mutation_strategy": mutation.mutation_strategy,
        "lineage_depth": lineage_depth,
        "supported": False,
        "expected_accept": False,
        "expected_status": mutation.expected_status,
        "accepted": "",
        "rejected": "",
        "false_accept": "",
        "verification_status": "",
        "verification_error_count": "",
        "first_verification_error": "",
        "rejection_rate": "",
        "ok": True,
        "result": "unsupported",
        "error_message": mutation.error_message,
    }


def build_rows(*, config: dict, environment: dict, run_id: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    false_accepts: list[str] = []
    unexpected_statuses: list[str] = []
    attack_cases = list(config["adversarial_attack_cases"])
    depths = [int(depth) for depth in config["depths"]]
    trials_per_attack = int(config["adversarial_trials_per_attack"])

    for attack_case in attack_cases:
        case_rows = 0
        for trial_index in range(trials_per_attack):
            depth = depths[0] if config.get("smoke") else depths[trial_index % len(depths)]
            trial_id = f"adversarial-{attack_case}-depth-{depth:02d}-trial-{trial_index:04d}"
            try:
                fixture = build_lineage_fixture(
                    global_seed=config["seed"],
                    depth=depth,
                    trial_index=trial_index,
                    requested_capability=config["requested_capability"],
                    min_confirmations=config["min_confirmations"],
                    runner=RUNNER_NAME,
                )
                mutation = mutate_fixture(
                    fixture=fixture,
                    attack_case=attack_case,
                    requested_capability=config["requested_capability"],
                    min_confirmations=config["min_confirmations"],
                )
            except Exception as exc:
                rows.append(_unsupported_row(
                    config=config,
                    environment=environment,
                    run_id=run_id,
                    attack_case=attack_case,
                    trial_id=trial_id,
                    lineage_depth=depth,
                    error_message=f"attack case could not be generated cleanly: {exc}",
                ))
                case_rows += 1
                break

            if not mutation.supported or mutation.proof is None:
                rows.append(_unsupported_row(
                    config=config,
                    environment=environment,
                    run_id=run_id,
                    attack_case=attack_case,
                    trial_id=trial_id,
                    lineage_depth=depth,
                    error_message=mutation.error_message,
                ))
                case_rows += 1
                break

            try:
                verification = verify_lineage_proof(
                    mutation.proof,
                    trusted_roots=mutation.trusted_roots,
                    requested_capability=mutation.requested_capability,
                    anchor_backend=fixture.anchor_backend,
                    min_confirmations=mutation.min_confirmations,
                    now=mutation.now,
                )
            except Exception as exc:
                rows.append({
                    **_base_row(
                        config=config,
                        environment=environment,
                        run_id=run_id,
                        trial_id=trial_id,
                        timestamp_utc=utc_timestamp(),
                    ),
                    "attack_case": attack_case,
                    "mutation_target": mutation.mutation_target,
                    "mutation_strategy": mutation.mutation_strategy,
                    "lineage_depth": depth,
                    "supported": True,
                    "expected_accept": False,
                    "expected_status": mutation.expected_status,
                    "accepted": "",
                    "rejected": "",
                    "false_accept": "",
                    "verification_status": "",
                    "verification_error_count": "",
                    "first_verification_error": "",
                    "rejection_rate": "",
                    "ok": False,
                    "result": "error",
                    "error_message": f"verification raised unexpectedly: {exc}",
                })
                case_rows += 1
                unexpected_statuses.append(f"{trial_id}: verifier raised {exc}")
                continue

            accepted = bool(verification.ok)
            rejected = not accepted
            false_accept = accepted
            first_error = verification.errors[0] if verification.errors else ""
            status_matches = verification.status == mutation.expected_status
            ok = rejected and status_matches
            result = "false_accept" if false_accept else "rejected"
            if rejected and not status_matches:
                result = "unexpected_status"

            row = {
                **_base_row(
                    config=config,
                    environment=environment,
                    run_id=run_id,
                    trial_id=trial_id,
                    timestamp_utc=utc_timestamp(),
                ),
                "attack_case": attack_case,
                "mutation_target": mutation.mutation_target,
                "mutation_strategy": mutation.mutation_strategy,
                "lineage_depth": depth,
                "supported": True,
                "expected_accept": False,
                "expected_status": mutation.expected_status,
                "accepted": accepted,
                "rejected": rejected,
                "false_accept": false_accept,
                "verification_status": verification.status,
                "verification_error_count": len(verification.errors),
                "first_verification_error": first_error,
                "rejection_rate": 1.0 if rejected else 0.0,
                "ok": ok,
                "result": result,
                "error_message": "" if ok else first_error,
            }
            rows.append(row)
            case_rows += 1
            if false_accept:
                false_accepts.append(f"{trial_id}: verifier accepted {attack_case}")
            elif not status_matches:
                unexpected_statuses.append(
                    f"{trial_id}: expected {mutation.expected_status}, got {verification.status}"
                )

        if case_rows == 0:
            rows.append(_unsupported_row(
                config=config,
                environment=environment,
                run_id=run_id,
                attack_case=attack_case,
                trial_id=f"adversarial-{attack_case}-unsupported",
                lineage_depth=depths[0],
                error_message="attack case produced no rows",
            ))

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
    csv_path = run_dir / "raw" / "adversarial_rejection.csv"
    write_csv(csv_path, rows, ADVERSARIAL_REJECTION_SCHEMA)
    validate_csv_exact_schema(csv_path, ADVERSARIAL_REJECTION_SCHEMA)
    validate_non_empty_csv(csv_path)
    validate_attack_cases_measured_or_unsupported(csv_path, config["adversarial_attack_cases"])
    if not config["allow_exploratory_failures"]:
        false_accepts = [
            row["trial_id"]
            for row in rows
            if row["supported"] is True and row["false_accept"] is True
        ]
        unexpected_statuses = [
            row["trial_id"]
            for row in rows
            if row["supported"] is True and row["result"] == "unexpected_status"
        ]
        errors = [
            row["trial_id"]
            for row in rows
            if row["supported"] is True and row["result"] == "error"
        ]
        if false_accepts:
            raise RuntimeError("supported adversarial cases were accepted: " + "; ".join(false_accepts[:5]))
        if unexpected_statuses:
            raise RuntimeError(
                "supported adversarial cases returned unexpected statuses: "
                + "; ".join(unexpected_statuses[:5])
            )
        if errors:
            raise RuntimeError("supported adversarial cases errored: " + "; ".join(errors[:5]))
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        print(f"adversarial rejection runner failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
