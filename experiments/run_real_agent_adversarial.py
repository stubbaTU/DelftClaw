"""Run adversarial lineage trials through real OpenClawAgent admission flows."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter_ns
from typing import Any

from ipv8.peer import Peer

from agent import LineageRuntimeConfig
from communication.community import CommunityLineageConfig, LineageProofPayload
from experiments.common.config import add_common_args, resolve_config
from experiments.common.environment import capture_environment
from experiments.common.io import create_run_directory, utc_timestamp, write_csv, write_json
from experiments.common.real_agent_lineage import (
    AlwaysAcceptVerifier,
    EXPECTED_STATUS,
    authority_pubkey,
    build_attack_setup,
    build_proof,
    build_runtime_agent,
    deterministic_identity,
    expected_join_accept,
    first_error,
    mode_flags,
    wait_for_status,
)
from experiments.common.validation import (
    REAL_AGENT_ADVERSARIAL_SCHEMA,
    validate_csv_exact_schema,
    validate_non_empty_csv,
    validate_real_agent_matrix_present,
)
from identity.lineage.store import write_json as write_lineage_json


RUNNER_NAME = "real_agent_adversarial"


async def _run_trial(
    *,
    config: dict[str, Any],
    environment: dict[str, Any],
    run_id: str,
    mode: str,
    attack_case: str,
    trial_index: int,
) -> dict[str, object]:
    trial_id = f"real-agent-{mode}-{attack_case}-trial-{trial_index:04d}"
    enabled, required = mode_flags(mode)
    root = deterministic_identity(
        int(config["seed"]), RUNNER_NAME, attack_case, trial_index, "root"
    )
    gatekeeper_identity = deterministic_identity(
        int(config["seed"]), RUNNER_NAME, attack_case, trial_index, "gatekeeper"
    )
    child_identity = deterministic_identity(
        int(config["seed"]), RUNNER_NAME, attack_case, trial_index, "child"
    )
    capability = str(config["requested_capability"])

    with TemporaryDirectory(prefix=f"{trial_id}-") as temp:
        trial_root = Path(temp)
        gatekeeper_package_path = trial_root / "gatekeeper" / "lineage" / "birth_package.json"
        child_package_path = trial_root / "child" / "lineage" / "birth_package.json"
        gatekeeper_proof = build_proof(
            root=root,
            subject=gatekeeper_identity,
            family_id=f"gatekeeper-{trial_id}",
            capability=capability,
            experiment_name=RUNNER_NAME,
        )
        trusted_roots = ({
            "agent_id": root.identity_hash,
            "authority_pubkey": authority_pubkey(root),
        },)
        write_lineage_json(gatekeeper_package_path, {
            "version": 1,
            "package_type": "lineage_birth_package_v1",
            "proof": gatekeeper_proof,
            "trusted_roots": list(trusted_roots),
        })

        setup = build_attack_setup(
            config=config,
            experiment_name=RUNNER_NAME,
            attack_case=attack_case,
            trial_index=trial_index,
            root=root,
            child=child_identity,
        )
        if setup.proof is not None:
            write_lineage_json(child_package_path, {
                "version": 1,
                "package_type": "lineage_birth_package_v1",
                "proof": setup.proof,
                "trusted_roots": list(setup.trusted_roots),
            })

        gatekeeper_lineage = LineageRuntimeConfig(
            enabled=enabled,
            required=required,
            btc_network="mock",
            min_anchor_confirmations=int(config["min_confirmations"]),
            birth_package_path=gatekeeper_package_path if enabled else None,
            cache_path=trial_root / "gatekeeper" / "lineage" / "cache.json",
            trusted_roots=trusted_roots if enabled else (),
            accepted_capabilities=setup.accepted_capabilities if enabled else (),
        )
        child_lineage = LineageRuntimeConfig(
            enabled=True,
            required=False,
            btc_network="mock",
            birth_package_path=child_package_path,
            cache_path=trial_root / "child" / "lineage" / "cache.json",
            trusted_roots=setup.trusted_roots,
        )
        gatekeeper = build_runtime_agent(
            gatekeeper_identity,
            trial_root / "gatekeeper",
            gatekeeper_lineage,
        )
        child = build_runtime_agent(
            setup.runtime_identity,
            trial_root / "child",
            child_lineage,
        )

        status: dict[str, Any] | None = None
        join_accepted: bool | str = ""
        duration_ms: float | str = ""
        error_message = ""
        captured_payloads: list[LineageProofPayload] = []
        try:
            await gatekeeper.start()
            await child.start()
            gatekeeper.seedbox.configure(verifier=AlwaysAcceptVerifier())
            if enabled:
                gatekeeper.seedbox.configure(lineage_config=CommunityLineageConfig(
                    enabled=True,
                    required=required,
                    trusted_roots=setup.trusted_roots,
                    min_anchor_confirmations=int(config["min_confirmations"]),
                    accepted_capabilities=setup.accepted_capabilities,
                    cache_path=trial_root / "gatekeeper" / "lineage" / "peer-cache.json",
                    challenge_timeout_s=float(config["real_agent_challenge_timeout_s"]),
                ))
                child.seedbox.configure(
                    lineage_proof_provider=lambda proof=setup.proof: proof
                )

            gatekeeper_peer = child.add_peer(
                gatekeeper.address[0],
                gatekeeper.address[1],
                gatekeeper.pubkey_hex,
            )
            child_peer = gatekeeper.add_peer(
                child.address[0],
                child.address[1],
                child.pubkey_hex,
            )

            original_ez_send = child.seedbox.ez_send
            if enabled and attack_case == "replayed_nonce_or_stale_proof":
                def _capture(peer: Peer, payload: Any) -> Any:
                    if isinstance(payload, LineageProofPayload):
                        captured_payloads.append(payload)
                    return original_ez_send(peer, payload)

                child.seedbox.ez_send = _capture  # type: ignore[method-assign]

            started_ns = perf_counter_ns()
            join_accepted = await asyncio.wait_for(
                child.seedbox.request_join(
                    gatekeeper_peer,
                    donation_txid=trial_id.encode("utf-8"),
                ),
                timeout=float(config["real_agent_join_timeout_s"]),
            )

            if enabled:
                expected_wire_status = (
                    "valid"
                    if attack_case == "replayed_nonce_or_stale_proof"
                    else EXPECTED_STATUS[attack_case]
                )
                status = await wait_for_status(
                    gatekeeper,
                    child_peer.mid.hex(),
                    timeout_s=float(config["real_agent_join_timeout_s"]),
                    expected_status=expected_wire_status,
                )
                if attack_case == "replayed_nonce_or_stale_proof":
                    if not captured_payloads:
                        raise RuntimeError("no lineage proof payload was captured for replay")
                    original_ez_send(gatekeeper_peer, captured_payloads[-1])
                    status = await wait_for_status(
                        gatekeeper,
                        child_peer.mid.hex(),
                        timeout_s=float(config["real_agent_join_timeout_s"]),
                        expected_status="replay",
                    )
            duration_ms = (perf_counter_ns() - started_ns) / 1_000_000
        except asyncio.TimeoutError:
            error_message = "real OpenClawAgent admission trial timed out"
        except Exception as exc:
            error_message = f"{type(exc).__name__}: {exc}"
        finally:
            await child.stop()
            await gatekeeper.stop()

        expected_join = expected_join_accept(mode, attack_case)
        expected_status = "" if not enabled else EXPECTED_STATUS[attack_case]
        actual_status = str(status.get("status", "")) if status else ""
        status_matches = (not enabled and status is None) or actual_status == expected_status
        join_matches = join_accepted == expected_join
        ok = bool(not error_message and join_matches and status_matches)
        if not error_message and not join_matches:
            error_message = f"expected join_accepted={expected_join}, got {join_accepted}"
        if not error_message and not status_matches:
            error_message = f"expected lineage_status={expected_status or '<none>'}, got {actual_status or '<none>'}"

        lineage_ok = bool(status.get("ok")) if status is not None else ""
        rejected = bool(status is not None and status.get("ok") is False)
        false_accept = bool(
            mode == "required"
            and attack_case not in {"valid_agent_baseline", "replayed_nonce_or_stale_proof"}
            and join_accepted is True
        )
        errors = status.get("errors", []) if status else []
        return {
            "schema_version": config["schema_version"],
            "run_id": run_id,
            "runner": RUNNER_NAME,
            "seed": config["seed"],
            "trial_id": trial_id,
            "timestamp_utc": utc_timestamp(),
            "git_commit": environment["git_commit"],
            "python_version": environment["python_version"],
            "platform": environment["platform"],
            "attack_case": attack_case,
            "agent_role": "joining_child",
            "runtime_class": "agent.runtime.OpenClawAgent",
            "admission_path": "SeedboxCommunity.request_join",
            "lineage_mode": mode,
            "lineage_enabled": enabled,
            "lineage_required": required,
            "proof_supplied": setup.proof_supplied if enabled else False,
            "mutation_target": setup.mutation_target,
            "mutation_strategy": setup.mutation_strategy,
            "expected_accept": expected_join,
            "join_accepted": join_accepted,
            "lineage_status": actual_status,
            "lineage_ok": lineage_ok,
            "rejected": rejected,
            "false_accept": false_accept,
            "duration_ms": duration_ms,
            "lineage_error_count": len(errors) if isinstance(errors, list) else "",
            "first_lineage_error": first_error(status),
            "anchor_backend": "mock",
            "btc_network": "mock",
            "ok": ok,
            "result": "measured" if ok else ("timeout" if "timed out" in error_message else "unexpected"),
            "error_message": error_message,
        }


async def _build_rows_async(
    *,
    config: dict[str, Any],
    environment: dict[str, Any],
    run_id: str,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for mode in config["real_agent_lineage_modes"]:
        for attack_case in config["real_agent_attack_cases"]:
            for trial_index in range(int(config["real_agent_trials_per_case"])):
                rows.append(await _run_trial(
                    config=config,
                    environment=environment,
                    run_id=run_id,
                    mode=mode,
                    attack_case=attack_case,
                    trial_index=trial_index,
                ))
    return rows


def build_rows(
    *,
    config: dict[str, Any],
    environment: dict[str, Any],
    run_id: str,
) -> list[dict[str, object]]:
    return asyncio.run(_build_rows_async(config=config, environment=environment, run_id=run_id))


def run(args: argparse.Namespace) -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    config = resolve_config(args.config, seed_override=args.seed, smoke=args.smoke)
    environment = capture_environment(repo_root)
    run_dir = create_run_directory(args.out, git_commit=str(environment["git_commit"]))
    config["config_path"] = str(Path(args.config).resolve())
    config["run_id"] = run_dir.name
    config["claim_boundary"] = (
        "real OpenClawAgent/IPv8 admission with mock anchor records; "
        "no Bitcoin RPC or OP_RETURN anchoring"
    )
    write_json(run_dir / "config.json", config)
    write_json(run_dir / "environment.json", environment)

    rows = build_rows(config=config, environment=environment, run_id=run_dir.name)
    path = run_dir / "raw" / "real_agent_adversarial.csv"
    write_csv(path, rows, REAL_AGENT_ADVERSARIAL_SCHEMA)
    validate_csv_exact_schema(path, REAL_AGENT_ADVERSARIAL_SCHEMA)
    validate_non_empty_csv(path)
    validate_real_agent_matrix_present(
        path,
        config["real_agent_lineage_modes"],
        config["real_agent_attack_cases"],
    )
    if not config["allow_exploratory_failures"]:
        failed = [str(row["trial_id"]) for row in rows if row["ok"] is False]
        if failed:
            raise RuntimeError("real-agent adversarial trial failures: " + "; ".join(failed[:5]))
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    args = parser.parse_args(argv)
    try:
        run_dir = run(args)
    except Exception as exc:
        print(f"real-agent adversarial runner failed: {exc}", file=sys.stderr)
        return 1
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
