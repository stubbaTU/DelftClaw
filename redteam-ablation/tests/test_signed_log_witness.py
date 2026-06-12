"""Witness / foreign-entry / downgrade surface of SignedAppendOnlyLog (Finding 1).

A *witness* entry is one where a reporter B records an action by a distinct
subject A and embeds A's own Ed25519 signature over a portable "claim" envelope
as cryptographic proof the underlying claim came from A's key. This module
covers:

* a valid B-witnesses-A append, then a clean ``verify_integrity``;
* ``verify_foreign_entry`` accepting a valid isolated witness entry, and
  rejecting each of: bad subject signature, identity-binding mismatch, claim
  details mismatch, malformed/short nonce;
* a cross-network subject failing the subject identity binding;
* the downgrade defense firing when a *self* entry smuggles a ``subject_*``
  field;
* each pre-write check in ``append_witness_event`` raising AND never persisting
  a chain entry.

The subject claim is signed over the canonical bytes the producer/verifier use
(``signed_log._canonical_bytes``), so the test exercises the real contract, not
a guess at the encoding.
"""

from __future__ import annotations

import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from redteam_ablation.primitives.identity import Ed25519Identity
from redteam_ablation.primitives.signed_log import (
    SignedAppendOnlyLog,
    _canonical_bytes,
    _stable_hash,
)

NETWORK = "MAINNET"


def _subject_id(pubkey: bytes, network: str = NETWORK) -> str:
    """SHA256(subject_pubkey || network) -- the identity binding the log checks."""
    return hashlib.sha256(pubkey + network.encode("utf-8")).hexdigest()


def _make_subject(network: str = NETWORK):
    """Return (private_key, pubkey_bytes, subject_id) for a subject A."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return priv, pub, _subject_id(pub, network)


def _build_claim(subject_id: str, action: str, details: dict, *, nonce_hex=None):
    """Build the portable claim envelope A signs (kind=claim, version=1, ...)."""
    return {
        "kind": "claim",
        "version": 1,
        "subject_id": subject_id,
        "action": action,
        "details_hash": _stable_hash(details),
        "claim_timestamp": "2026-05-29T00:00:00+00:00",
        "nonce": (nonce_hex if nonce_hex is not None else "0" * 32),
    }


def _sign_claim(priv: Ed25519PrivateKey, claim: dict) -> bytes:
    """A signs the canonical bytes of the claim envelope."""
    return priv.sign(_canonical_bytes(claim))


def _valid_witness_inputs(network: str = NETWORK):
    """Return a fully-consistent kwargs dict for ``append_witness_event``."""
    sub_priv, sub_pub, sub_id = _make_subject(network)
    action = "tool_execution_success"
    details = {"tool": "send_email", "to": "ally@example.com"}
    claim = _build_claim(sub_id, action, details)
    sig = _sign_claim(sub_priv, claim)
    return {
        "subject_id": sub_id,
        "subject_pubkey": sub_pub,
        "subject_claim": claim,
        "subject_signature": sig,
        "action": action,
        "details": details,
    }


# --- happy path: B witnesses A, then verify_integrity is clean ---------------


def test_valid_witness_append_verifies_clean(tmp_path):
    reporter = Ed25519Identity(network=NETWORK)
    log = SignedAppendOnlyLog(reporter, tmp_path / "witness.log")

    inputs = _valid_witness_inputs()
    entry = log.append_witness_event(
        reporter_id=reporter.reporter_id, **inputs
    )

    assert entry["kind"] == "witness"
    assert entry["previous_hash"] == "GENESIS"

    ok, errors = log.verify_integrity()
    assert ok is True, errors
    assert errors == []


def test_witness_entry_chains_after_self_entry(tmp_path):
    reporter = Ed25519Identity(network=NETWORK)
    log = SignedAppendOnlyLog(reporter, tmp_path / "chain.log")
    rid = reporter.reporter_id

    first = log.append_event(
        reporter_id=rid, subject_id=rid, action="a", details={"i": 1}
    )
    second = log.append_witness_event(
        reporter_id=rid, **_valid_witness_inputs()
    )
    assert second["previous_hash"] == first["entry_hash"]

    ok, errors = log.verify_integrity()
    assert ok is True, errors


# --- verify_foreign_entry: accept a valid isolated witness entry -------------


def _foreign_witness_entry(tmp_path, network: str = NETWORK) -> dict:
    """Produce one valid, fully-formed witness entry to test in isolation."""
    reporter = Ed25519Identity(network=network)
    log = SignedAppendOnlyLog(reporter, tmp_path / "foreign.log")
    return log.append_witness_event(
        reporter_id=reporter.reporter_id, **_valid_witness_inputs(network)
    )


def test_foreign_entry_accepts_valid_witness(tmp_path):
    entry = _foreign_witness_entry(tmp_path)
    ok, errors = SignedAppendOnlyLog.verify_foreign_entry(entry, NETWORK)
    assert ok is True, errors
    assert errors == []


# --- verify_foreign_entry: reject each tampered variant ----------------------


def test_foreign_entry_rejects_bad_subject_signature(tmp_path):
    entry = _foreign_witness_entry(tmp_path)
    sig = entry["subject_signature"]
    # Flip one nibble of the (valid-length) subject signature.
    flipped = ("1" if sig[0] != "1" else "2") + sig[1:]
    entry["subject_signature"] = flipped

    ok, errors = SignedAppendOnlyLog.verify_foreign_entry(entry, NETWORK)
    assert ok is False
    # entry_hash binds the subject sig, so the hash mismatch fires too -- but the
    # subject-signature failure must be among the reported errors.
    assert any("subject signature" in e for e in errors), errors


def test_foreign_entry_rejects_identity_binding_mismatch(tmp_path):
    entry = _foreign_witness_entry(tmp_path)
    # Corrupt the subject_id so SHA256(subject_pubkey||network) no longer matches.
    entry["subject_id"] = "f" * 64

    ok, errors = SignedAppendOnlyLog.verify_foreign_entry(entry, NETWORK)
    assert ok is False
    assert any("subject identity binding mismatch" in e for e in errors), errors


def test_foreign_entry_rejects_claim_details_mismatch(tmp_path):
    entry = _foreign_witness_entry(tmp_path)
    # The claim's details_hash no longer matches hash(entry.details).
    claim = dict(entry["subject_claim"])
    claim["details_hash"] = "0" * 64
    entry["subject_claim"] = claim

    ok, errors = SignedAppendOnlyLog.verify_foreign_entry(entry, NETWORK)
    assert ok is False
    assert any("details_hash does not match" in e for e in errors), errors


def test_foreign_entry_rejects_malformed_short_nonce(tmp_path):
    entry = _foreign_witness_entry(tmp_path)
    # An 8-byte (16 hex char) nonce is too short -- the schema requires 16 bytes.
    claim = dict(entry["subject_claim"])
    claim["nonce"] = "00" * 8
    entry["subject_claim"] = claim

    ok, errors = SignedAppendOnlyLog.verify_foreign_entry(entry, NETWORK)
    assert ok is False
    assert any("nonce length mismatch" in e for e in errors), errors


# --- cross-network subject -> binding failure --------------------------------


def test_cross_network_subject_fails_binding_at_write(tmp_path):
    """A subject bound to a different network fails the identity-binding check.

    The reporter is on MAINNET but the subject_id derives from the subject
    pubkey over TESTNET, so ``SHA256(pubkey || MAINNET) != subject_id``.
    """
    reporter = Ed25519Identity(network=NETWORK)
    log = SignedAppendOnlyLog(reporter, tmp_path / "xnet.log")

    # Subject's id was bound on a DIFFERENT network than the reporter's.
    inputs = _valid_witness_inputs(network="TESTNET")
    # Re-sign the claim so ONLY the binding (not the claim consistency) fails:
    # the claim still references the TESTNET subject_id consistently.
    with pytest.raises(ValueError, match="subject identity binding mismatch"):
        log.append_witness_event(reporter_id=reporter.reporter_id, **inputs)

    # Nothing was persisted: only the header line exists.
    contents = (tmp_path / "xnet.log").read_text(encoding="utf-8").splitlines()
    data_lines = [ln for ln in contents if ln.strip() and not ln.startswith("===")]
    assert data_lines == []


# --- downgrade defense: a self entry that smuggles a subject_* field ---------


def test_self_entry_smuggling_subject_field_rejected_foreign(tmp_path):
    reporter = Ed25519Identity(network=NETWORK)
    log = SignedAppendOnlyLog(reporter, tmp_path / "self.log")
    rid = reporter.reporter_id
    entry = log.append_event(
        reporter_id=rid, subject_id=rid, action="a", details={"i": 1}
    )
    # Smuggle a subject_pubkey into a self entry. verify_foreign_entry must fire
    # the downgrade defense (a self entry must not carry subject_* fields).
    entry["subject_pubkey"] = "ab" * 32

    ok, errors = SignedAppendOnlyLog.verify_foreign_entry(entry, NETWORK)
    assert ok is False
    assert any("downgrade defense" in e for e in errors), errors


def test_self_entry_smuggling_subject_field_rejected_in_chain(tmp_path):
    reporter = Ed25519Identity(network=NETWORK)
    log_path = tmp_path / "self_chain.log"
    log = SignedAppendOnlyLog(reporter, log_path)
    rid = reporter.reporter_id
    entry = log.append_event(
        reporter_id=rid, subject_id=rid, action="a", details={"i": 1}
    )
    # Rewrite the persisted self entry with a smuggled subject_claim field.
    lines = log_path.read_text(encoding="utf-8").splitlines(keepends=True)
    persisted = json.loads(lines[1])
    persisted["subject_claim"] = {"kind": "claim"}
    lines[1] = json.dumps(persisted) + "\n"
    log_path.write_text("".join(lines), encoding="utf-8")

    ok, errors = log.verify_integrity()
    assert ok is False
    assert any("downgrade defense" in e for e in errors), errors


# --- pre-write checks raise AND never persist --------------------------------


def _assert_nothing_persisted(log_path) -> None:
    contents = log_path.read_text(encoding="utf-8").splitlines()
    data_lines = [ln for ln in contents if ln.strip() and not ln.startswith("===")]
    assert data_lines == [], f"a rejected witness entry was persisted: {data_lines}"


def test_prewrite_short_signature_raises_and_persists_nothing(tmp_path):
    reporter = Ed25519Identity(network=NETWORK)
    log_path = tmp_path / "short_sig.log"
    log = SignedAppendOnlyLog(reporter, log_path)

    inputs = _valid_witness_inputs()
    inputs["subject_signature"] = b"\x00" * 8  # not 64 bytes

    with pytest.raises(ValueError):
        log.append_witness_event(reporter_id=reporter.reporter_id, **inputs)
    _assert_nothing_persisted(log_path)


def test_prewrite_short_pubkey_raises_and_persists_nothing(tmp_path):
    reporter = Ed25519Identity(network=NETWORK)
    log_path = tmp_path / "short_pub.log"
    log = SignedAppendOnlyLog(reporter, log_path)

    inputs = _valid_witness_inputs()
    inputs["subject_pubkey"] = b"\x00" * 8  # not 32 bytes

    with pytest.raises(ValueError):
        log.append_witness_event(reporter_id=reporter.reporter_id, **inputs)
    _assert_nothing_persisted(log_path)


def test_prewrite_claim_mismatch_raises_and_persists_nothing(tmp_path):
    reporter = Ed25519Identity(network=NETWORK)
    log_path = tmp_path / "claim_mismatch.log"
    log = SignedAppendOnlyLog(reporter, log_path)

    inputs = _valid_witness_inputs()
    # Claim's action disagrees with the entry's action (consistency check #3).
    bad_claim = copy.deepcopy(inputs["subject_claim"])
    bad_claim["action"] = "something_else"
    inputs["subject_claim"] = bad_claim

    with pytest.raises(ValueError, match="action does not match"):
        log.append_witness_event(reporter_id=reporter.reporter_id, **inputs)
    _assert_nothing_persisted(log_path)


def test_prewrite_bad_subject_signature_raises_and_persists_nothing(tmp_path):
    reporter = Ed25519Identity(network=NETWORK)
    log_path = tmp_path / "bad_sig.log"
    log = SignedAppendOnlyLog(reporter, log_path)

    inputs = _valid_witness_inputs()
    # A correct-length but wrong signature: 64 bytes that don't verify.
    inputs["subject_signature"] = b"\x01" * 64

    with pytest.raises(ValueError, match="subject signature"):
        log.append_witness_event(reporter_id=reporter.reporter_id, **inputs)
    _assert_nothing_persisted(log_path)


def test_prewrite_malformed_nonce_raises_and_persists_nothing(tmp_path):
    reporter = Ed25519Identity(network=NETWORK)
    log_path = tmp_path / "bad_nonce.log"
    log = SignedAppendOnlyLog(reporter, log_path)

    sub_priv, sub_pub, sub_id = _make_subject()
    action = "tool_execution_success"
    details = {"tool": "send_email"}
    # Build a claim with a non-hex nonce, then sign it so ONLY the nonce schema
    # check fails (the subject signature over this exact claim is still valid).
    claim = _build_claim(sub_id, action, details, nonce_hex="zz" * 16)
    sig = _sign_claim(sub_priv, claim)

    with pytest.raises(ValueError, match="nonce"):
        log.append_witness_event(
            reporter_id=reporter.reporter_id,
            subject_id=sub_id,
            subject_pubkey=sub_pub,
            subject_claim=claim,
            subject_signature=sig,
            action=action,
            details=details,
        )
    _assert_nothing_persisted(log_path)
