"""Proof and policy mutations for adversarial lineage experiments."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from experiments.common.fixtures import LineageFixture, deterministic_private_key, public_key_hex
from identity.lineage.canonical import canonical_hash
from identity.lineage.models import LineageProof
from identity.lineage.revocation import issue_revocation_event


RUNNER_NAME = "adversarial_rejection"

DEFAULT_ATTACK_CASES = [
    "tampered_child_agent_id",
    "tampered_child_operational_pubkey",
    "tampered_parent_signature",
    "wrong_trusted_root",
    "broken_merkle_leaf_hash",
    "broken_merkle_proof_step",
    "broken_merkle_root",
    "wrong_anchor_id",
    "anchor_root_mismatch",
    "insufficient_confirmations",
    "expired_certificate",
    "missing_capability",
    "signed_revocation",
    "unauthorized_revocation_signer",
    "malformed_revocation_event",
]


EXPECTED_STATUS = {
    "tampered_child_agent_id": "invalid",
    "tampered_child_operational_pubkey": "invalid",
    "tampered_parent_signature": "invalid",
    "wrong_trusted_root": "invalid",
    "broken_merkle_leaf_hash": "invalid",
    "broken_merkle_proof_step": "invalid",
    "broken_merkle_root": "invalid",
    "wrong_anchor_id": "unanchored",
    "anchor_root_mismatch": "unanchored",
    "insufficient_confirmations": "insufficient_confirmations",
    "expired_certificate": "expired",
    "missing_capability": "invalid",
    "signed_revocation": "revoked",
    "unauthorized_revocation_signer": "invalid",
    "malformed_revocation_event": "invalid",
}


@dataclass(frozen=True)
class MutationCase:
    proof: LineageProof | None
    trusted_roots: list[dict[str, str]]
    requested_capability: str | None
    min_confirmations: int
    mutation_target: str
    mutation_strategy: str
    expected_status: str
    supported: bool = True
    error_message: str = ""
    now: datetime | None = None


def unsupported_case(attack_case: str, message: str) -> MutationCase:
    return MutationCase(
        proof=None,
        trusted_roots=[],
        requested_capability=None,
        min_confirmations=0,
        mutation_target="unsupported",
        mutation_strategy="unsupported",
        expected_status=EXPECTED_STATUS.get(attack_case, ""),
        supported=False,
        error_message=message,
    )


def _different_hash(*, trial_seed: str, attack_case: str, field: str) -> str:
    return canonical_hash({
        "runner": RUNNER_NAME,
        "trial_seed": trial_seed,
        "attack_case": attack_case,
        "field": field,
    })


def _flip_signature(signature: str) -> str:
    try:
        data = bytearray(base64.b64decode(signature, validate=True))
    except ValueError:
        return "not-valid-base64"
    if not data:
        return "AA=="
    data[0] ^= 0x01
    return base64.b64encode(bytes(data)).decode("ascii")


def _parse_proof(data: dict[str, Any]) -> LineageProof:
    return LineageProof.from_dict(data)


def mutate_fixture(
    *,
    fixture: LineageFixture,
    attack_case: str,
    requested_capability: str,
    min_confirmations: int,
) -> MutationCase:
    """Return a normally parseable mutated proof or verification context."""

    if attack_case not in EXPECTED_STATUS:
        return unsupported_case(attack_case, f"attack case is not implemented by this runner: {attack_case}")

    proof_data = fixture.proof.to_dict()
    leaf = proof_data["leaf_certificate"]
    expected_status = EXPECTED_STATUS[attack_case]

    if attack_case == "tampered_child_agent_id":
        leaf["child_agent_id"] = f"mallory-{fixture.trial_seed[:16]}"
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="leaf_certificate.child_agent_id",
            mutation_strategy="replace_with_deterministic_wrong_agent_id",
            expected_status=expected_status,
        )

    if attack_case == "tampered_child_operational_pubkey":
        leaf["child_operational_pubkey"] = _different_hash(
            trial_seed=fixture.trial_seed,
            attack_case=attack_case,
            field="child_operational_pubkey",
        )
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="leaf_certificate.child_operational_pubkey",
            mutation_strategy="replace_with_deterministic_wrong_pubkey",
            expected_status=expected_status,
        )

    if attack_case == "tampered_parent_signature":
        leaf["parent_signature"] = _flip_signature(str(leaf["parent_signature"]))
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="leaf_certificate.parent_signature",
            mutation_strategy="flip_first_signature_byte",
            expected_status=expected_status,
        )

    if attack_case == "wrong_trusted_root":
        wrong_root_key = deterministic_private_key(f"{fixture.trial_seed}|wrong_trusted_root")
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=[{
                "agent_id": f"wrong-root-{fixture.trial_seed[:12]}",
                "authority_pubkey": public_key_hex(wrong_root_key),
            }],
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="trusted_roots",
            mutation_strategy="verify_against_unrelated_root",
            expected_status=expected_status,
        )

    if attack_case == "broken_merkle_leaf_hash":
        proof_data["merkle_leaf_hash"] = _different_hash(
            trial_seed=fixture.trial_seed,
            attack_case=attack_case,
            field="merkle_leaf_hash",
        )
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="merkle_leaf_hash",
            mutation_strategy="replace_with_deterministic_wrong_hash",
            expected_status=expected_status,
        )

    if attack_case == "broken_merkle_proof_step":
        if not proof_data["merkle_proof"]:
            return unsupported_case(attack_case, "fixture did not produce a Merkle proof step to mutate")
        proof_data["merkle_proof"][0]["hash"] = _different_hash(
            trial_seed=fixture.trial_seed,
            attack_case=attack_case,
            field="merkle_proof[0].hash",
        )
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="merkle_proof[0].hash",
            mutation_strategy="replace_sibling_hash",
            expected_status=expected_status,
        )

    if attack_case == "broken_merkle_root":
        proof_data["merkle_root"] = _different_hash(
            trial_seed=fixture.trial_seed,
            attack_case=attack_case,
            field="merkle_root",
        )
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="merkle_root",
            mutation_strategy="replace_top_level_root",
            expected_status=expected_status,
        )

    if attack_case == "wrong_anchor_id":
        proof_data["anchor_id"] = f"mock-wrong-{fixture.trial_seed[:16]}"
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="anchor_id",
            mutation_strategy="replace_top_level_anchor_id",
            expected_status=expected_status,
        )

    if attack_case == "anchor_root_mismatch":
        proof_data["anchor_record"]["merkle_root"] = _different_hash(
            trial_seed=fixture.trial_seed,
            attack_case=attack_case,
            field="anchor_record.merkle_root",
        )
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="anchor_record.merkle_root",
            mutation_strategy="replace_anchor_record_root",
            expected_status=expected_status,
        )

    if attack_case == "insufficient_confirmations":
        proof_data["anchor_record"]["confirmations"] = 0
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=max(min_confirmations, 1),
            mutation_target="anchor_record.confirmations",
            mutation_strategy="lower_confirmations_below_policy",
            expected_status=expected_status,
        )

    if attack_case == "expired_certificate":
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="verification_time",
            mutation_strategy="verify_after_certificate_expiry",
            expected_status=expected_status,
            now=datetime(2040, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        )

    if attack_case == "missing_capability":
        missing = f"missing-capability-{fixture.trial_seed[:12]}"
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=missing,
            min_confirmations=min_confirmations,
            mutation_target="requested_capability",
            mutation_strategy="request_absent_capability_label",
            expected_status=expected_status,
        )

    if attack_case == "signed_revocation":
        leaf_parent_index = len(fixture.agent_ids) - 2
        event = issue_revocation_event(
            revoker_signing_key=fixture.authority_keys[leaf_parent_index],
            certificate_id=fixture.proof.leaf_certificate.certificate_id,
            family_id=fixture.proof.leaf_certificate.family_id,
            revoked_by_agent_id=fixture.agent_ids[leaf_parent_index],
            revoked_by_pubkey=public_key_hex(fixture.authority_keys[leaf_parent_index]),
            reason="adversarial signed revocation",
            created_at="2026-01-01T00:00:00Z",
        )
        proof_data["revocation_events"] = [event.to_dict()]
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="revocation_events",
            mutation_strategy="append_authorized_signed_revocation",
            expected_status=expected_status,
        )

    if attack_case == "unauthorized_revocation_signer":
        attacker_key = deterministic_private_key(f"{fixture.trial_seed}|unauthorized_revocation_signer")
        event = issue_revocation_event(
            revoker_signing_key=attacker_key,
            certificate_id=fixture.proof.leaf_certificate.certificate_id,
            family_id=fixture.proof.leaf_certificate.family_id,
            revoked_by_agent_id=f"mallory-{fixture.trial_seed[:12]}",
            revoked_by_pubkey=public_key_hex(attacker_key),
            reason="unauthorized revocation attempt",
            created_at="2026-01-01T00:00:00Z",
        )
        proof_data["revocation_events"] = [event.to_dict()]
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="revocation_events",
            mutation_strategy="append_signed_revocation_from_unrelated_key",
            expected_status=expected_status,
        )

    if attack_case == "malformed_revocation_event":
        proof_data["revocation_events"] = [{
            "certificate_id": fixture.proof.leaf_certificate.certificate_id,
            "reason": "missing required signed revocation fields",
        }]
        return MutationCase(
            proof=_parse_proof(proof_data),
            trusted_roots=fixture.trusted_roots,
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            mutation_target="revocation_events[0]",
            mutation_strategy="drop_required_revocation_fields",
            expected_status=expected_status,
        )

    return unsupported_case(attack_case, f"attack case is not implemented by this runner: {attack_case}")
