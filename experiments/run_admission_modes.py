"""Run IPv8 SeedboxCommunity lineage admission-mode trials."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter_ns

from cryptography.hazmat.primitives import serialization
from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from admission.donation_verifier import DonationVerification
from communication.community import (
    CommunityLineageConfig,
    LineageProofPayload,
    SeedboxCommunity,
    _peer_operational_pubkey_hexes,
    lineage_proof_signing_payload,
)
from experiments.common.config import add_common_args, resolve_config
from experiments.common.environment import capture_environment
from experiments.common.fixtures import deterministic_private_key
from experiments.common.io import create_run_directory, utc_timestamp, write_csv, write_json
from experiments.common.validation import (
    ADMISSION_MODES_SCHEMA,
    validate_admission_matrix_present,
    validate_csv_exact_schema,
    validate_non_empty_csv,
)
from identity.lineage.canonical import canonical_hash, certificate_hash
from identity.lineage.certificates import issue_child_certificate, utc_now_iso
from identity.lineage.merkle import merkle_proof, merkle_root
from identity.lineage.mock_anchor import MockAnchorBackend
from identity.lineage.models import CertificateBatch, LineageProof


RUNNER_NAME = "admission_modes"


class AlwaysAcceptVerifier:
    def verify(self, txid_hex: str) -> DonationVerification:
        return DonationVerification(accepted=True, paid_sats=10_000, confirmations=1)


@dataclass
class TwoSeedboxes:
    svc_a: IPv8
    svc_b: IPv8
    sb_a: SeedboxCommunity
    sb_b: SeedboxCommunity
    peer_a_for_b: Peer
    peer_b_for_a: Peer


def _build_node(port: int, key_path: Path) -> IPv8:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.set_address("127.0.0.1")
    builder.add_key("anchor", "curve25519", str(key_path))
    builder.add_overlay("SeedboxCommunity", "anchor", [], [], {}, [("started",)])
    return IPv8(
        builder.finalize(),
        extra_communities={"SeedboxCommunity": SeedboxCommunity},
    )


async def _start_two_seedboxes(root: Path) -> TwoSeedboxes:
    from ipv8.keyvault.crypto import default_eccrypto

    key_a = root / "a.key"
    key_b = root / "b.key"
    key_a.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())
    key_b.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())

    svc_a = _build_node(port=0, key_path=key_a)
    svc_b = _build_node(port=0, key_path=key_b)
    await svc_a.start()
    await svc_b.start()

    sb_a = next(o for o in svc_a.overlays if isinstance(o, SeedboxCommunity))
    sb_b = next(o for o in svc_b.overlays if isinstance(o, SeedboxCommunity))

    peer_b_for_a = Peer(sb_b.my_peer.public_key, address=sb_b.endpoint.get_address())
    peer_a_for_b = Peer(sb_a.my_peer.public_key, address=sb_a.endpoint.get_address())
    sb_a.network.add_verified_peer(peer_b_for_a)
    sb_b.network.add_verified_peer(peer_a_for_b)

    return TwoSeedboxes(
        svc_a=svc_a,
        svc_b=svc_b,
        sb_a=sb_a,
        sb_b=sb_b,
        peer_a_for_b=peer_a_for_b,
        peer_b_for_a=peer_b_for_a,
    )


async def _stop_two_seedboxes(nodes: TwoSeedboxes) -> None:
    await nodes.svc_a.stop()
    await nodes.svc_b.stop()


def _pubkey_hex(key) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _proof_for_peer(
    peer: Peer,
    *,
    seed: int,
    trial_index: int,
    requested_capability: str,
) -> tuple[dict, tuple[dict[str, str], ...]]:
    prefix = f"{seed}|{RUNNER_NAME}|proof|{peer.mid.hex()}|{trial_index}"
    root_key = deterministic_private_key(f"{prefix}|root-key")
    child_key = deterministic_private_key(f"{prefix}|child-key")
    operational_pubkey = sorted(_peer_operational_pubkey_hexes(peer), key=len)[0]
    certificate = issue_child_certificate(
        parent_signing_key=root_key,
        family_id=f"admission-mode-family-{canonical_hash({'prefix': prefix})[:12]}",
        parent_agent_id="root-agent",
        parent_authority_pubkey=_pubkey_hex(root_key),
        child_agent_id=peer.mid.hex(),
        child_authority_pubkey=_pubkey_hex(child_key),
        child_operational_pubkey=operational_pubkey,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2036-01-01T00:00:00Z",
        capabilities=[requested_capability],
        anchor_policy={"required": True, "min_confirmations": 0},
    )
    leaves = [certificate_hash(certificate)]
    root = merkle_root(leaves)
    batch = CertificateBatch(
        batch_id=canonical_hash({
            "certificate_id": certificate.certificate_id,
            "created_at": utc_now_iso(),
            "kind": "lineage_certificate_batch_v1",
        }),
        merkle_root=root,
        leaf_hashes=leaves,
        certificate_ids=[certificate.certificate_id],
        created_at=utc_now_iso(),
    )
    anchor = MockAnchorBackend(confirmations=1).create_anchor(batch)
    proof = LineageProof(
        leaf_certificate=certificate,
        chain=[],
        merkle_leaf_hash=leaves[0],
        merkle_proof=merkle_proof(leaves, 0),
        merkle_root=root,
        anchor_id=anchor.anchor_id,
        anchor_record=anchor,
    )
    trusted_roots = ({
        "agent_id": "root-agent",
        "authority_pubkey": _pubkey_hex(root_key),
    },)
    return proof.to_dict(), trusted_roots


async def _wait_for_status(
    sb: SeedboxCommunity,
    peer_mid: bytes,
    *,
    timeout_s: float,
) -> dict | None:
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        status = sb.lineage_peer_status.get(peer_mid)
        if status is not None:
            return status
        await asyncio.sleep(0.025)
    return None


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


def _mode_flags(mode: str) -> tuple[bool, bool]:
    if mode == "disabled":
        return False, False
    if mode == "optional":
        return True, False
    if mode == "required":
        return True, True
    raise ValueError(f"unknown admission mode: {mode}")


def _expected_join_accepted(mode: str, peer_case: str) -> bool | None:
    if peer_case == "replayed_nonce":
        return None
    if mode in {"disabled", "optional"}:
        return True
    return peer_case == "valid_proof"


def _expected_lineage_status(mode: str, peer_case: str) -> str:
    if mode == "disabled":
        return ""
    return {
        "valid_proof": "valid",
        "invalid_proof": "invalid",
        "missing_proof": "missing",
        "replayed_nonce": "replay",
    }[peer_case]


def _lineage_config(mode: str, trusted_roots: tuple[dict[str, str], ...], config: dict) -> CommunityLineageConfig:
    enabled, required = _mode_flags(mode)
    return CommunityLineageConfig(
        enabled=enabled,
        required=required,
        trusted_roots=trusted_roots,
        min_anchor_confirmations=int(config["min_confirmations"]),
        accepted_capabilities=(str(config["requested_capability"]),),
        challenge_timeout_s=float(config["admission_challenge_timeout_s"]),
    )


def _first_error(status: dict | None) -> str:
    if not status:
        return ""
    errors = status.get("errors", [])
    if isinstance(errors, list) and errors:
        return str(errors[0])
    return ""


def _row_from_trial(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    trial_id: str,
    mode: str,
    peer_case: str,
    proof_supplied: bool,
    proof_valid_expected: bool,
    join_accepted: bool | str,
    expected_join_accepted: bool | str,
    status: dict | None,
    duration_ms: float | str,
    result: str,
    ok: bool,
    error_message: str,
) -> dict[str, object]:
    enabled, required = _mode_flags(mode)
    lineage_recorded = status is not None
    lineage_ok: object = bool(status.get("ok")) if status is not None else ""
    lineage_status = str(status.get("status", "")) if status is not None else ""
    lineage_error_count: object = ""
    if status is not None:
        errors = status.get("errors", [])
        lineage_error_count = len(errors) if isinstance(errors, list) else ""

    join_success_rate: object = ""
    if isinstance(join_accepted, bool):
        join_success_rate = 1.0 if join_accepted else 0.0

    invalid_peer_rejection_rate: object = 0.0
    if peer_case != "valid_proof":
        rejected = (join_accepted is False) or (status is not None and status.get("ok") is False)
        invalid_peer_rejection_rate = 1.0 if rejected else 0.0

    return {
        **_base_row(
            config=config,
            environment=environment,
            run_id=run_id,
            trial_id=trial_id,
            timestamp_utc=utc_timestamp(),
        ),
        "mode": mode,
        "peer_case": peer_case,
        "lineage_enabled": enabled,
        "lineage_required": required,
        "proof_supplied": proof_supplied,
        "proof_valid_expected": proof_valid_expected,
        "join_accepted": join_accepted,
        "expected_join_accepted": expected_join_accepted,
        "lineage_status_recorded": lineage_recorded,
        "lineage_ok": lineage_ok,
        "lineage_status": lineage_status,
        "lineage_error_count": lineage_error_count,
        "first_lineage_error": _first_error(status),
        "join_success_rate": join_success_rate,
        "invalid_peer_rejection_rate": invalid_peer_rejection_rate,
        "duration_ms": duration_ms,
        "ok": ok,
        "result": result,
        "error_message": error_message,
    }


def _unsupported_row(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    trial_id: str,
    mode: str,
    peer_case: str,
    error_message: str,
) -> dict[str, object]:
    return _row_from_trial(
        config=config,
        environment=environment,
        run_id=run_id,
        trial_id=trial_id,
        mode=mode,
        peer_case=peer_case,
        proof_supplied=False,
        proof_valid_expected=False,
        join_accepted="",
        expected_join_accepted="",
        status=None,
        duration_ms="",
        result="unsupported",
        ok=True,
        error_message=error_message,
    )


async def _run_join_trial(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    mode: str,
    peer_case: str,
    trial_index: int,
) -> dict[str, object]:
    trial_id = f"admission-{mode}-{peer_case}-trial-{trial_index:04d}"
    with TemporaryDirectory(prefix=f"{trial_id}-") as temp_root:
        nodes = await _start_two_seedboxes(Path(temp_root))
        try:
            proof, trusted_roots = _proof_for_peer(
                nodes.peer_b_for_a,
                seed=int(config["seed"]),
                trial_index=trial_index,
                requested_capability=str(config["requested_capability"]),
            )
            if peer_case == "invalid_proof":
                proof["leaf_certificate"]["child_operational_pubkey"] = "00" * 32

            nodes.sb_a.configure(
                verifier=AlwaysAcceptVerifier(),
                lineage_config=_lineage_config(mode, trusted_roots, config),
            )
            if peer_case in {"valid_proof", "invalid_proof"}:
                nodes.sb_b.configure(lineage_proof_provider=lambda proof=proof: proof)

            started_ns = perf_counter_ns()
            status: dict | None = None
            join_accepted: bool | str = ""
            try:
                join_accepted = await asyncio.wait_for(
                    nodes.sb_b.request_join(
                        nodes.peer_a_for_b,
                        donation_txid=f"{mode}|{peer_case}|{trial_index}".encode("utf-8"),
                    ),
                    timeout=float(config["admission_join_timeout_s"]),
                )
                duration_ms: float | str = (perf_counter_ns() - started_ns) / 1_000_000
            except asyncio.TimeoutError:
                duration_ms = (perf_counter_ns() - started_ns) / 1_000_000
                expected_join = _expected_join_accepted(mode, peer_case)
                return _row_from_trial(
                    config=config,
                    environment=environment,
                    run_id=run_id,
                    trial_id=trial_id,
                    mode=mode,
                    peer_case=peer_case,
                    proof_supplied=peer_case != "missing_proof",
                    proof_valid_expected=peer_case == "valid_proof",
                    join_accepted="",
                    expected_join_accepted=expected_join if expected_join is not None else "",
                    status=None,
                    duration_ms=duration_ms,
                    result="timeout",
                    ok=False,
                    error_message="join request timed out",
                )

            if mode != "disabled":
                status = await _wait_for_status(
                    nodes.sb_a,
                    nodes.peer_b_for_a.mid,
                    timeout_s=float(config["admission_join_timeout_s"]),
                )

            expected_join = _expected_join_accepted(mode, peer_case)
            expected_status = _expected_lineage_status(mode, peer_case)
            join_matches = expected_join is None or join_accepted == expected_join
            if mode == "disabled":
                status_matches = status is None
            else:
                status_matches = status is not None and status.get("status") == expected_status
            ok = bool(join_matches and status_matches)
            details: list[str] = []
            if not join_matches:
                details.append(f"expected join_accepted={expected_join}, got {join_accepted}")
            if not status_matches:
                actual = status.get("status") if status else "<none>"
                details.append(f"expected lineage_status={expected_status or '<none>'}, got {actual}")

            return _row_from_trial(
                config=config,
                environment=environment,
                run_id=run_id,
                trial_id=trial_id,
                mode=mode,
                peer_case=peer_case,
                proof_supplied=peer_case != "missing_proof",
                proof_valid_expected=peer_case == "valid_proof",
                join_accepted=join_accepted,
                expected_join_accepted=expected_join if expected_join is not None else "",
                status=status,
                duration_ms=duration_ms,
                result="measured" if ok else "unexpected",
                ok=ok,
                error_message="; ".join(details),
            )
        finally:
            await _stop_two_seedboxes(nodes)


async def _run_replayed_nonce_trial(
    *,
    config: dict,
    environment: dict,
    run_id: str,
    mode: str,
    trial_index: int,
) -> dict[str, object]:
    peer_case = "replayed_nonce"
    trial_id = f"admission-{mode}-{peer_case}-trial-{trial_index:04d}"
    if mode == "disabled":
        return _unsupported_row(
            config=config,
            environment=environment,
            run_id=run_id,
            trial_id=trial_id,
            mode=mode,
            peer_case=peer_case,
            error_message="lineage disabled mode has no lineage nonce challenge to replay",
        )

    with TemporaryDirectory(prefix=f"{trial_id}-") as temp_root:
        nodes = await _start_two_seedboxes(Path(temp_root))
        try:
            proof, trusted_roots = _proof_for_peer(
                nodes.peer_b_for_a,
                seed=int(config["seed"]),
                trial_index=trial_index,
                requested_capability=str(config["requested_capability"]),
            )
            nodes.sb_a.configure(lineage_config=_lineage_config(mode, trusted_roots, config))
            proof_json = json.dumps(proof, sort_keys=True, separators=(",", ":")).encode("utf-8")
            nonce = canonical_hash({
                "seed": config["seed"],
                "mode": mode,
                "trial_index": trial_index,
                "case": peer_case,
            }).encode("ascii")[:32]
            signature = nodes.sb_b._sign_lineage_payload(
                lineage_proof_signing_payload(nonce, proof_json)
            )

            started_ns = perf_counter_ns()
            SeedboxCommunity.on_lineage_proof.__wrapped__(
                nodes.sb_a,
                nodes.peer_b_for_a,
                LineageProofPayload(nonce, proof_json, signature),
            )
            duration_ms = (perf_counter_ns() - started_ns) / 1_000_000
            status = nodes.sb_a.lineage_peer_status.get(nodes.peer_b_for_a.mid)
            ok = status is not None and status.get("ok") is False and status.get("status") == "replay"
            return _row_from_trial(
                config=config,
                environment=environment,
                run_id=run_id,
                trial_id=trial_id,
                mode=mode,
                peer_case=peer_case,
                proof_supplied=True,
                proof_valid_expected=False,
                join_accepted="",
                expected_join_accepted="",
                status=status,
                duration_ms=duration_ms,
                result="measured" if ok else "unexpected",
                ok=ok,
                error_message="" if ok else "replayed proof nonce was not recorded as replay",
            )
        finally:
            await _stop_two_seedboxes(nodes)


async def _build_rows_async(*, config: dict, environment: dict, run_id: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    trials_per_case = int(config["admission_trials_per_case"])
    for mode in config["admission_modes"]:
        for peer_case in config["admission_peer_cases"]:
            for trial_index in range(trials_per_case):
                if peer_case == "replayed_nonce":
                    row = await _run_replayed_nonce_trial(
                        config=config,
                        environment=environment,
                        run_id=run_id,
                        mode=mode,
                        trial_index=trial_index,
                    )
                else:
                    row = await _run_join_trial(
                        config=config,
                        environment=environment,
                        run_id=run_id,
                        mode=mode,
                        peer_case=peer_case,
                        trial_index=trial_index,
                    )
                rows.append(row)
    return rows


def build_rows(*, config: dict, environment: dict, run_id: str) -> list[dict[str, object]]:
    return asyncio.run(_build_rows_async(config=config, environment=environment, run_id=run_id))


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
    csv_path = run_dir / "raw" / "admission_modes.csv"
    write_csv(csv_path, rows, ADMISSION_MODES_SCHEMA)
    validate_csv_exact_schema(csv_path, ADMISSION_MODES_SCHEMA)
    validate_non_empty_csv(csv_path)
    validate_admission_matrix_present(csv_path, config["admission_modes"], config["admission_peer_cases"])

    if not config["allow_exploratory_failures"]:
        unexpected = [
            str(row["trial_id"])
            for row in rows
            if row["result"] not in {"measured", "unsupported", "timeout"} or row["ok"] is False
        ]
        if unexpected:
            raise RuntimeError("admission mode trial failures: " + "; ".join(unexpected[:5]))
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception as exc:
        print(f"admission modes runner failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
