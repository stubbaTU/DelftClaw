"""TDD red-step tests for redteam.demo.witness_tamper.tamper."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from identity.openclaw_identity import OpenClawIdentity
from redteam.demo.witness_tamper.tamper import tamper_witness_entry
from redteam.primitives.signed_log import (
    SignedAppendOnlyLog,
    _canonical_bytes,
    _stable_hash,
)


def _make_identity(tmp_path: Path, name: str) -> OpenClawIdentity:
    key_path = tmp_path / f"{name}.json"
    return OpenClawIdentity(network="TESTNET", key_path=str(key_path))


def _make_subject_claim(
    identity: OpenClawIdentity,
    action: str,
    details: dict,
    *,
    claim_timestamp: str = "2025-01-01T00:00:00+00:00",
    nonce_hex: str = "00112233445566778899aabbccddeeff",
) -> tuple[dict, bytes, bytes]:
    claim = {
        "kind": "claim",
        "version": 1,
        "subject_id": identity.identity_hash,
        "action": action,
        "details_hash": _stable_hash(details),
        "claim_timestamp": claim_timestamp,
        "nonce": nonce_hex,
    }
    sig = identity.sign(_canonical_bytes(claim))
    return claim, identity.public_key, sig


@pytest.fixture
def valid_witness_entry(tmp_path: Path):
    subject = _make_identity(tmp_path, "a")
    witness = _make_identity(tmp_path, "b")
    details = {"amount": 5, "recipient": "charity_x"}
    claim, sub_pk, sub_sig = _make_subject_claim(subject, "donation", details)
    log = SignedAppendOnlyLog(witness, str(tmp_path / "b.jsonl"))
    entry = log.append_witness_event(
        reporter_id=witness.identity_hash,
        subject_id=subject.identity_hash,
        subject_pubkey=sub_pk,
        subject_claim=claim,
        subject_signature=sub_sig,
        action="donation",
        details=details,
    )
    return entry, witness, subject


def test_tamper_changes_amount(valid_witness_entry):
    entry, witness, _ = valid_witness_entry
    tampered = tamper_witness_entry(entry, witness)
    assert tampered["details"]["amount"] == 5000


def test_tamper_recomputes_details_hash(valid_witness_entry):
    entry, witness, _ = valid_witness_entry
    tampered = tamper_witness_entry(entry, witness)
    assert tampered["details_hash"] == _stable_hash(tampered["details"])


def test_tamper_wrapper_verifies_alone(valid_witness_entry, tmp_path: Path):
    entry, witness, subject = valid_witness_entry
    tampered = tamper_witness_entry(entry, witness)
    # Forge a subject_claim aligned with the new details to isolate the
    # wrapper-only consistency check.
    new_claim, _, new_sig = _make_subject_claim(
        subject, "donation", tampered["details"]
    )
    aligned = deepcopy(tampered)
    aligned["subject_claim"] = new_claim
    aligned["subject_signature"] = new_sig.hex()
    # Re-sign and re-hash the wrapper after swapping claim/sig.
    payload = dict(aligned)
    payload.pop("entry_hash", None)
    payload.pop("signature", None)
    aligned["signature"] = witness.sign(_canonical_bytes(payload)).hex()
    hashable = dict(aligned)
    hashable.pop("entry_hash", None)
    hashable.pop("signature", None)
    aligned["entry_hash"] = _stable_hash(hashable)
    ok, errors = SignedAppendOnlyLog.verify_foreign_entry(aligned, witness.network)
    assert ok is True, errors


def test_tamper_caught_by_verify_foreign_entry(valid_witness_entry):
    entry, witness, _ = valid_witness_entry
    tampered = tamper_witness_entry(entry, witness)
    ok, errors = SignedAppendOnlyLog.verify_foreign_entry(
        tampered, witness.network
    )
    assert ok is False
    assert (
        "subject_claim.details_hash does not match hash(entry.details)"
        in errors
    )


def test_tamper_leaves_subject_claim_intact(valid_witness_entry):
    entry, witness, _ = valid_witness_entry
    original_claim = deepcopy(entry["subject_claim"])
    tampered = tamper_witness_entry(entry, witness)
    assert tampered["subject_claim"] == original_claim


def test_tamper_does_not_mutate_input(valid_witness_entry):
    entry, witness, _ = valid_witness_entry
    snapshot = deepcopy(entry)
    tamper_witness_entry(entry, witness)
    assert entry == snapshot
