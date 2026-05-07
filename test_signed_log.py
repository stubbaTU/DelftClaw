"""TDD red-step tests for SignedAppendOnlyLog.

These tests intentionally fail until ``redteam.primitives.signed_log`` is
implemented. They exercise the sign-then-chain append flow, tamper
detection (content, signature, public-key swap), the hash chain
invariants, the empty-log case, and document the wrinkle that the plain
``AppendOnlyLog`` does not understand signed entries.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from identity.openclaw_identity import OpenClawIdentity
from security.subq2_accountability.append_log import AppendOnlyLog
from redteam.primitives.signed_log import SignedAppendOnlyLog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_identity(tmp_path: Path, name: str = "test_key.pem") -> OpenClawIdentity:
    """Create a fresh OpenClawIdentity backed by a key file in tmp_path."""
    return OpenClawIdentity(network="MAINNET", key_path=str(tmp_path / name))


def _canonical(payload: dict) -> bytes:
    """Local canonical-bytes mirror; intentionally re-implemented for tests."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _stable_hash_hex(payload: dict) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _make_subject_claim(
    identity: OpenClawIdentity,
    action: str,
    details: dict,
    *,
    claim_timestamp: str = "2025-01-01T00:00:00+00:00",
    nonce_hex: str = "00112233445566778899aabbccddeeff",
) -> tuple[dict, bytes, bytes]:
    """Build and Ed25519-sign a deterministic claim.

    Returns ``(claim_dict, subject_pubkey_bytes, subject_signature_bytes)``.
    Determinism (explicit timestamp + nonce) makes the bytes signed
    reproducible across runs so tampering tests don't flake.
    """
    claim = {
        "kind": "claim",
        "version": 1,
        "subject_id": str(identity.identity_hash),
        "action": action,
        "details_hash": _stable_hash_hex(details),
        "claim_timestamp": claim_timestamp,
        "nonce": nonce_hex,
    }
    sig = identity.sign(_canonical(claim))
    return claim, identity.public_key, sig


def _recompute_reporter_sig_and_hash(
    entry: dict, identity: OpenClawIdentity
) -> dict:
    """Re-sign and re-hash an entry so the chain stays internally consistent.

    Use after mutating a witness entry's *subject* fields (or any other
    field) when you want everything *except* the targeted check to still
    pass — i.e. only the subject-side check should fire on verify.
    """
    payload = dict(entry)
    payload.pop("entry_hash", None)
    payload.pop("signature", None)
    sig = identity.sign(_canonical(payload)).hex()
    entry["signature"] = sig
    hashable = dict(entry)
    hashable.pop("entry_hash", None)
    hashable.pop("signature", None)
    # Note: chain hash covers signature too via override (signature popped
    # only from hashable for the *hash* input; the *signed* payload had no
    # signature). Mirror the producer behavior exactly: hash input is
    # entry minus entry_hash and signature.
    entry["entry_hash"] = hashlib.sha256(_canonical(hashable)).hexdigest()
    return entry


def _append_three(wrapper: SignedAppendOnlyLog, identity: OpenClawIdentity) -> None:
    """Write three deterministic entries through the signed wrapper."""
    reporter = str(identity.identity_hash)
    for index in range(3):
        wrapper.append_event(
            reporter_id=reporter,
            subject_id=reporter,
            action=f"test_action_{index}",
            details={"index": index, "key": "value"},
        )


def _load_lines(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.readlines()


def _dump_lines(path: str, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)


def _entry_line_indices(lines: list[str]) -> list[int]:
    """Return indices of lines that are actual JSON entries (skip header/blank)."""
    indices: list[int] = []
    for i, line in enumerate(lines):
        if line.startswith("===") or not line.strip():
            continue
        indices.append(i)
    return indices


def _read_json_lines(path: str) -> list[tuple[int, str]]:
    """Return [(line_number, raw_line), ...] for non-header non-empty lines."""
    out: list[tuple[int, str]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for i, line in enumerate(handle):
            if line.startswith("===") or not line.strip():
                continue
            out.append((i, line))
    return out


def _write_lines(path: str, lines: list[str]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)


def _mutate_entry(path: str, entry_index: int, mutation) -> None:
    """1-indexed ``entry_index``. Apply ``mutation(entry_dict)`` and write back."""
    lines = _load_lines(path)
    seen = 0
    for i, line in enumerate(lines):
        if line.startswith("===") or not line.strip():
            continue
        seen += 1
        if seen == entry_index:
            entry = json.loads(line)
            mutation(entry)
            lines[i] = json.dumps(entry) + "\n"
            break
    _write_lines(path, lines)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_self_entry_has_kind_field(tmp_path: Path) -> None:
    """Every self entry must carry an explicit ``kind: "self"``."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    entries = wrapper.read_entries()
    assert len(entries) == 3
    for entry in entries:
        assert entry.get("kind") == "self"

    ok, errors = wrapper.verify_integrity()
    assert ok is True, errors


def test_witness_entry_round_trip(tmp_path: Path) -> None:
    """Happy path: B records A's signed claim. Wrapper + CLI both verify."""
    identity_a = _make_identity(tmp_path, "key_a.pem")  # subject
    identity_b = _make_identity(tmp_path, "key_b.pem")  # reporter

    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    details = {"k": "v", "n": 1}
    claim, subject_pubkey, subject_sig = _make_subject_claim(
        identity_a, "observed_action", details
    )

    entry = wrapper.append_witness_event(
        reporter_id=str(identity_b.identity_hash),
        subject_id=str(identity_a.identity_hash),
        subject_pubkey=subject_pubkey,
        subject_claim=claim,
        subject_signature=subject_sig,
        action="observed_action",
        details=details,
    )

    assert entry["kind"] == "witness"
    assert entry["reporter_id"] == str(identity_b.identity_hash)
    assert entry["subject_id"] == str(identity_a.identity_hash)
    assert entry["action"] == "observed_action"
    assert entry["details"] == details
    assert entry["details_hash"] == _stable_hash_hex(details)
    assert entry["subject_pubkey"] == subject_pubkey.hex()
    assert entry["subject_signature"] == subject_sig.hex()
    assert entry["subject_claim"] == claim
    # Reporter signing key is B's, not A's.
    assert entry["reporter_pubkey"] == identity_b.public_key.hex()

    ok, errors = wrapper.verify_integrity()
    assert ok is True, errors


def test_mixed_self_and_witness_chain(tmp_path: Path) -> None:
    """A chain interleaving self and witness entries verifies cleanly."""
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")

    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    # B writes one self entry first.
    wrapper.append_event(
        reporter_id=str(identity_b.identity_hash),
        subject_id=str(identity_b.identity_hash),
        action="b_self_action",
        details={"step": 1},
    )

    # B records A's signed claim as a witness entry.
    details = {"step": 2, "by": "a"}
    claim, pk, sig = _make_subject_claim(
        identity_a, "a_action", details, nonce_hex="11" * 16
    )
    wrapper.append_witness_event(
        reporter_id=str(identity_b.identity_hash),
        subject_id=str(identity_a.identity_hash),
        subject_pubkey=pk,
        subject_claim=claim,
        subject_signature=sig,
        action="a_action",
        details=details,
    )

    # B writes another self entry after.
    wrapper.append_event(
        reporter_id=str(identity_b.identity_hash),
        subject_id=str(identity_b.identity_hash),
        action="b_self_action_2",
        details={"step": 3},
    )

    entries = wrapper.read_entries()
    assert len(entries) == 3
    assert [e["kind"] for e in entries] == ["self", "witness", "self"]

    ok, errors = wrapper.verify_integrity()
    assert ok is True, errors


def test_one_subject_claim_carried_by_two_witnesses(tmp_path: Path) -> None:
    """The same A-signed claim, witnessed independently by B and by C.

    Demonstrates the "narrow claim" design choice: A signs once, multiple
    reporters can each independently record the same signed claim into
    their own logs, and each log verifies independently.
    """
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    identity_c = _make_identity(tmp_path, "key_c.pem")

    details = {"event": "broadcast", "seq": 7}
    claim, pk, sig = _make_subject_claim(
        identity_a, "broadcast_action", details, nonce_hex="22" * 16
    )

    log_b = str(tmp_path / "log_b.jsonl")
    wrapper_b = SignedAppendOnlyLog(identity_b, log_b)
    wrapper_b.append_witness_event(
        reporter_id=str(identity_b.identity_hash),
        subject_id=str(identity_a.identity_hash),
        subject_pubkey=pk,
        subject_claim=claim,
        subject_signature=sig,
        action="broadcast_action",
        details=details,
    )

    log_c = str(tmp_path / "log_c.jsonl")
    wrapper_c = SignedAppendOnlyLog(identity_c, log_c)
    wrapper_c.append_witness_event(
        reporter_id=str(identity_c.identity_hash),
        subject_id=str(identity_a.identity_hash),
        subject_pubkey=pk,
        subject_claim=claim,
        subject_signature=sig,
        action="broadcast_action",
        details=details,
    )

    ok_b, errs_b = wrapper_b.verify_integrity()
    assert ok_b is True, errs_b
    ok_c, errs_c = wrapper_c.verify_integrity()
    assert ok_c is True, errs_c

    # Each entry's reporter_id is the *witness's* id, not A's.
    entries_b = wrapper_b.read_entries()
    entries_c = wrapper_c.read_entries()
    assert entries_b[0]["reporter_id"] == str(identity_b.identity_hash)
    assert entries_c[0]["reporter_id"] == str(identity_c.identity_hash)
    # But both bind the same subject claim verbatim.
    assert entries_b[0]["subject_claim"] == entries_c[0]["subject_claim"]
    assert entries_b[0]["subject_signature"] == entries_c[0]["subject_signature"]


# ---------------------------------------------------------------------------
# Group 3 — producer rejection: append_witness_event must raise, never write
# ---------------------------------------------------------------------------


def _witness_kwargs(
    identity_a: OpenClawIdentity,
    identity_b: OpenClawIdentity,
    *,
    action: str = "act",
    details: dict | None = None,
    nonce_hex: str = "33" * 16,
):
    if details is None:
        details = {"d": 1}
    claim, pk, sig = _make_subject_claim(
        identity_a, action, details, nonce_hex=nonce_hex
    )
    return {
        "reporter_id": str(identity_b.identity_hash),
        "subject_id": str(identity_a.identity_hash),
        "subject_pubkey": pk,
        "subject_claim": claim,
        "subject_signature": sig,
        "action": action,
        "details": details,
    }


def _assert_no_log_written(log_path: str) -> None:
    p = Path(log_path)
    if not p.exists():
        return
    text = p.read_text(encoding="utf-8")
    # Strip header / blank lines.
    real_entries = [
        line for line in text.splitlines()
        if line and not line.startswith("===")
    ]
    assert real_entries == [], f"witness entry was persisted despite rejection: {real_entries!r}"


def test_witness_rejects_bad_subject_signature(tmp_path: Path) -> None:
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    kwargs = _witness_kwargs(identity_a, identity_b)
    # Replace the signature with all-zero bytes of correct length.
    kwargs["subject_signature"] = b"\x00" * 64

    with pytest.raises(ValueError):
        wrapper.append_witness_event(**kwargs)
    _assert_no_log_written(log_path)


def test_witness_rejects_subject_id_binding_mismatch(tmp_path: Path) -> None:
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    kwargs = _witness_kwargs(identity_a, identity_b)
    # Wrong subject_id — does not derive from subject_pubkey + network.
    kwargs["subject_id"] = "f" * 64

    with pytest.raises(ValueError):
        wrapper.append_witness_event(**kwargs)
    _assert_no_log_written(log_path)


def test_witness_rejects_inconsistent_action(tmp_path: Path) -> None:
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    kwargs = _witness_kwargs(identity_a, identity_b, action="claim_action")
    # Entry's action disagrees with claim's action.
    kwargs["action"] = "different_entry_action"

    with pytest.raises(ValueError):
        wrapper.append_witness_event(**kwargs)
    _assert_no_log_written(log_path)


def test_witness_rejects_inconsistent_details_hash(tmp_path: Path) -> None:
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    kwargs = _witness_kwargs(
        identity_a, identity_b, details={"original": True}
    )
    # The claim was signed over hash({"original": True}); pass different details.
    kwargs["details"] = {"swapped": True}

    with pytest.raises(ValueError):
        wrapper.append_witness_event(**kwargs)
    _assert_no_log_written(log_path)


def test_witness_rejects_malformed_pubkey_length(tmp_path: Path) -> None:
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    kwargs = _witness_kwargs(identity_a, identity_b)
    # 31 bytes instead of 32.
    kwargs["subject_pubkey"] = b"\x00" * 31

    with pytest.raises(ValueError):
        wrapper.append_witness_event(**kwargs)
    _assert_no_log_written(log_path)


def test_witness_rejects_malformed_signature_length(tmp_path: Path) -> None:
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    kwargs = _witness_kwargs(identity_a, identity_b)
    # 63 bytes instead of 64.
    kwargs["subject_signature"] = b"\x00" * 63

    with pytest.raises(ValueError):
        wrapper.append_witness_event(**kwargs)
    _assert_no_log_written(log_path)


def test_witness_rejects_missing_claim_timestamp(tmp_path: Path) -> None:
    """Producer rejects a claim that's missing the claim_timestamp field."""
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    kwargs = _witness_kwargs(identity_a, identity_b)
    # Drop claim_timestamp from the claim. The signature won't match either
    # but the claim-consistency check fires before the signature check.
    bad_claim = dict(kwargs["subject_claim"])
    bad_claim.pop("claim_timestamp", None)
    kwargs["subject_claim"] = bad_claim

    with pytest.raises(ValueError):
        wrapper.append_witness_event(**kwargs)
    _assert_no_log_written(log_path)


def test_witness_rejects_short_nonce(tmp_path: Path) -> None:
    """Producer rejects a claim whose nonce is shorter than 16 bytes."""
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    kwargs = _witness_kwargs(identity_a, identity_b)
    # 4 hex chars = 2 bytes; valid hex, but too short.
    bad_claim = dict(kwargs["subject_claim"])
    bad_claim["nonce"] = "abcd"
    kwargs["subject_claim"] = bad_claim

    with pytest.raises(ValueError):
        wrapper.append_witness_event(**kwargs)
    _assert_no_log_written(log_path)


# ---------------------------------------------------------------------------
# Group 4 — verifier tamper detection on witness entries
# Each test mutates one witness entry on disk, then recomputes the reporter
# signature + entry_hash so the chain stays internally consistent except for
# the targeted check.
# ---------------------------------------------------------------------------


def _setup_witness_log(
    tmp_path: Path, *, name: str = "log.jsonl"
) -> tuple[OpenClawIdentity, OpenClawIdentity, SignedAppendOnlyLog, str]:
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    log_path = str(tmp_path / name)
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    details = {"k": "v"}
    claim, pk, sig = _make_subject_claim(
        identity_a, "obs", details, nonce_hex="44" * 16
    )
    wrapper.append_witness_event(
        reporter_id=str(identity_b.identity_hash),
        subject_id=str(identity_a.identity_hash),
        subject_pubkey=pk,
        subject_claim=claim,
        subject_signature=sig,
        action="obs",
        details=details,
    )
    return identity_a, identity_b, wrapper, log_path


def _mutate_and_repair(
    log_path: str,
    entry_index: int,
    mutation,
    reporter_identity: OpenClawIdentity,
) -> None:
    """Apply ``mutation`` then recompute reporter sig + entry_hash."""

    def _wrap(entry: dict) -> None:
        mutation(entry)
        _recompute_reporter_sig_and_hash(entry, reporter_identity)

    _mutate_entry(log_path, entry_index, _wrap)


def test_witness_tamper_subject_signature_zeroed(tmp_path: Path) -> None:
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)

    _mutate_and_repair(
        log_path, 1,
        lambda e: e.update(subject_signature="00" * 64),
        identity_b,
    )

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("subject signature verification failed" in err for err in errors)


def test_witness_tamper_subject_pubkey_swap_binding_fires(tmp_path: Path) -> None:
    """Swap subject_pubkey only — identity binding fires (subject_id no longer derives)."""
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)
    other = _make_identity(tmp_path, "other.pem")

    _mutate_and_repair(
        log_path, 1,
        lambda e: e.update(subject_pubkey=other.public_key.hex()),
        identity_b,
    )

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("subject identity binding mismatch" in err for err in errors)


def test_witness_tamper_consistent_pubkey_and_id_swap(tmp_path: Path) -> None:
    """Swap both pubkey AND subject_id consistently — binding passes but subject sig fails."""
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)
    other = _make_identity(tmp_path, "other.pem")

    def _swap(entry: dict) -> None:
        entry["subject_pubkey"] = other.public_key.hex()
        entry["subject_id"] = str(other.identity_hash)
        # Also patch the claim's subject_id so claim consistency stays
        # internally aligned — this isolates the *signature* failure.
        entry["subject_claim"] = dict(entry["subject_claim"])
        entry["subject_claim"]["subject_id"] = str(other.identity_hash)

    _mutate_and_repair(log_path, 1, _swap, identity_b)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("subject signature verification failed" in err for err in errors)


def test_witness_tamper_action_in_entry_only(tmp_path: Path) -> None:
    """Mutate entry.action; claim.action unchanged → claim consistency fires."""
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)

    _mutate_and_repair(
        log_path, 1,
        lambda e: e.update(action="evil_action"),
        identity_b,
    )

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("subject_claim.action" in err for err in errors)


def test_witness_tamper_action_in_claim_only(tmp_path: Path) -> None:
    """Mutate claim.action; entry.action unchanged → claim consistency fires."""
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)

    def _mutate(entry: dict) -> None:
        entry["subject_claim"] = dict(entry["subject_claim"])
        entry["subject_claim"]["action"] = "evil_action"

    _mutate_and_repair(log_path, 1, _mutate, identity_b)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any(
        "subject_claim.action" in err
        or "subject signature verification failed" in err
        for err in errors
    )


def test_witness_tamper_details_breaks_details_hash(tmp_path: Path) -> None:
    """Mutate entry.details; details_hash recomputes differently → claim mismatch."""
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)

    def _mutate(entry: dict) -> None:
        entry["details"] = {"swapped": True}
        # details_hash field should also be updated to match the new details
        # so that the *primary* failure is "claim.details_hash != recomputed".
        entry["details_hash"] = _stable_hash_hex({"swapped": True})

    _mutate_and_repair(log_path, 1, _mutate, identity_b)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("details_hash" in err for err in errors)


def test_witness_tamper_claim_timestamp_removed(tmp_path: Path) -> None:
    """Drop claim_timestamp from the claim → envelope-schema check fires."""
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)

    def _mutate(entry: dict) -> None:
        entry["subject_claim"] = dict(entry["subject_claim"])
        entry["subject_claim"].pop("claim_timestamp", None)

    _mutate_and_repair(log_path, 1, _mutate, identity_b)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("claim_timestamp" in err for err in errors)


def test_witness_tamper_nonce_truncated(tmp_path: Path) -> None:
    """Truncate the nonce to 4 hex chars → either subject-sig or envelope-schema fires."""
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)

    def _mutate(entry: dict) -> None:
        entry["subject_claim"] = dict(entry["subject_claim"])
        entry["subject_claim"]["nonce"] = "abcd"

    _mutate_and_repair(log_path, 1, _mutate, identity_b)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    # Mutating the claim bytes invalidates the subject signature; the
    # envelope-schema check on nonce length also fires. Either is acceptable
    # — what matters is the entry is rejected.
    assert any(
        "subject signature verification failed" in err
        or "nonce length mismatch" in err
        for err in errors
    )


# ---------------------------------------------------------------------------
# Group 5 — missing-field + downgrade defenses
# ---------------------------------------------------------------------------


def test_witness_missing_subject_pubkey(tmp_path: Path) -> None:
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)

    _mutate_and_repair(
        log_path, 1,
        lambda e: e.pop("subject_pubkey", None),
        identity_b,
    )

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("missing subject_pubkey" in err for err in errors)


def test_witness_missing_subject_signature(tmp_path: Path) -> None:
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)

    _mutate_and_repair(
        log_path, 1,
        lambda e: e.pop("subject_signature", None),
        identity_b,
    )

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("missing subject_signature" in err for err in errors)


def test_witness_missing_subject_claim(tmp_path: Path) -> None:
    identity_a, identity_b, wrapper, log_path = _setup_witness_log(tmp_path)

    _mutate_and_repair(
        log_path, 1,
        lambda e: e.pop("subject_claim", None),
        identity_b,
    )

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("missing subject_claim" in err for err in errors)


def test_entry_missing_kind(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)
    _append_three(wrapper, identity)

    _mutate_and_repair(
        log_path, 1,
        lambda e: e.pop("kind", None),
        identity,
    )

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("missing or unknown kind" in err for err in errors)


def test_entry_unknown_kind_value(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)
    _append_three(wrapper, identity)

    _mutate_and_repair(
        log_path, 1,
        lambda e: e.update(kind="delegate"),
        identity,
    )

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("missing or unknown kind" in err for err in errors)


def test_self_entry_carrying_subject_signature_rejected(tmp_path: Path) -> None:
    """Downgrade defense: a self entry with subject fields is rejected."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)
    _append_three(wrapper, identity)

    # Smuggle a fake subject_signature into a self entry. Re-sign + re-hash
    # so the *only* failure is the downgrade defense.
    def _smuggle(entry: dict) -> None:
        entry["subject_signature"] = "00" * 64
        entry["subject_pubkey"] = "00" * 32
        entry["subject_claim"] = {
            "kind": "claim", "version": 1, "subject_id": "0" * 64,
            "action": "x", "details_hash": "0" * 64,
            "claim_timestamp": "2025-01-01T00:00:00+00:00",
            "nonce": "00" * 16,
        }

    _mutate_and_repair(log_path, 1, _smuggle, identity)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert any("downgrade defense" in err for err in errors)


# ---------------------------------------------------------------------------
# Group 6 — CLI verifier mirror coverage for witness entries
# ---------------------------------------------------------------------------


_REPO_ROOT = Path(__file__).resolve().parent


def _run_cli_verify(log_path: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "redteam.primitives.verify",
            "--log",
            log_path,
            "--network",
            "MAINNET",
        ],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
        timeout=30,
    )


def test_cli_verifies_clean_witness_round_trip(tmp_path: Path) -> None:
    identity_a = _make_identity(tmp_path, "key_a.pem")
    identity_b = _make_identity(tmp_path, "key_b.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_b, log_path)

    # Mixed chain: self, witness, self.
    wrapper.append_event(
        reporter_id=str(identity_b.identity_hash),
        subject_id=str(identity_b.identity_hash),
        action="b1",
        details={"i": 0},
    )
    details = {"x": 9}
    claim, pk, sig = _make_subject_claim(
        identity_a, "wact", details, nonce_hex="55" * 16
    )
    wrapper.append_witness_event(
        reporter_id=str(identity_b.identity_hash),
        subject_id=str(identity_a.identity_hash),
        subject_pubkey=pk,
        subject_claim=claim,
        subject_signature=sig,
        action="wact",
        details=details,
    )
    wrapper.append_event(
        reporter_id=str(identity_b.identity_hash),
        subject_id=str(identity_b.identity_hash),
        action="b2",
        details={"i": 2},
    )

    result = _run_cli_verify(log_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Verified 3 entries: OK" in result.stdout


def test_cli_detects_witness_subject_signature_zeroed(tmp_path: Path) -> None:
    identity_a, identity_b, _wrapper, log_path = _setup_witness_log(tmp_path)
    _mutate_and_repair(
        log_path, 1,
        lambda e: e.update(subject_signature="00" * 64),
        identity_b,
    )
    result = _run_cli_verify(log_path)
    assert result.returncode == 1
    assert "subject signature verification failed" in (result.stdout + result.stderr)


def test_cli_detects_witness_pubkey_swap_binding(tmp_path: Path) -> None:
    identity_a, identity_b, _wrapper, log_path = _setup_witness_log(tmp_path)
    other = _make_identity(tmp_path, "other.pem")
    _mutate_and_repair(
        log_path, 1,
        lambda e: e.update(subject_pubkey=other.public_key.hex()),
        identity_b,
    )
    result = _run_cli_verify(log_path)
    assert result.returncode == 1
    assert "subject identity binding mismatch" in (result.stdout + result.stderr)


def test_cli_detects_witness_action_in_entry_only(tmp_path: Path) -> None:
    identity_a, identity_b, _wrapper, log_path = _setup_witness_log(tmp_path)
    _mutate_and_repair(
        log_path, 1,
        lambda e: e.update(action="evil"),
        identity_b,
    )
    result = _run_cli_verify(log_path)
    assert result.returncode == 1
    assert "subject_claim.action" in (result.stdout + result.stderr)


def test_cli_detects_witness_details_hash_mismatch(tmp_path: Path) -> None:
    identity_a, identity_b, _wrapper, log_path = _setup_witness_log(tmp_path)

    def _mutate(entry: dict) -> None:
        entry["details"] = {"swapped": True}
        entry["details_hash"] = _stable_hash_hex({"swapped": True})

    _mutate_and_repair(log_path, 1, _mutate, identity_b)
    result = _run_cli_verify(log_path)
    assert result.returncode == 1
    assert "details_hash" in (result.stdout + result.stderr)


def test_cli_detects_missing_subject_claim(tmp_path: Path) -> None:
    identity_a, identity_b, _wrapper, log_path = _setup_witness_log(tmp_path)
    _mutate_and_repair(
        log_path, 1,
        lambda e: e.pop("subject_claim", None),
        identity_b,
    )
    result = _run_cli_verify(log_path)
    assert result.returncode == 1
    assert "missing subject_claim" in (result.stdout + result.stderr)


def test_cli_detects_self_entry_with_subject_fields(tmp_path: Path) -> None:
    """CLI rejects a self entry that smuggled in subject fields."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)
    _append_three(wrapper, identity)

    def _smuggle(entry: dict) -> None:
        entry["subject_signature"] = "00" * 64

    _mutate_and_repair(log_path, 1, _smuggle, identity)

    result = _run_cli_verify(log_path)
    assert result.returncode == 1
    assert "downgrade defense" in (result.stdout + result.stderr)


def test_cli_detects_unknown_kind(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)
    _append_three(wrapper, identity)
    _mutate_and_repair(
        log_path, 1,
        lambda e: e.update(kind="delegate"),
        identity,
    )
    result = _run_cli_verify(log_path)
    assert result.returncode == 1
    assert "unknown kind" in (result.stdout + result.stderr)


def test_cli_detects_witness_consistent_pubkey_and_id_swap(tmp_path: Path) -> None:
    """CLI mirror of test_witness_tamper_consistent_pubkey_and_id_swap.

    Swap subject_pubkey AND subject_id (and the claim's subject_id) to a
    different identity's values so binding passes and claim consistency
    stays internally aligned. The subject signature was made with the
    original identity's secret key, so it must fail under the new pubkey.
    """
    identity_a, identity_b, _wrapper, log_path = _setup_witness_log(tmp_path)
    other = _make_identity(tmp_path, "other.pem")

    def _swap(entry: dict) -> None:
        entry["subject_pubkey"] = other.public_key.hex()
        entry["subject_id"] = str(other.identity_hash)
        entry["subject_claim"] = dict(entry["subject_claim"])
        entry["subject_claim"]["subject_id"] = str(other.identity_hash)

    _mutate_and_repair(log_path, 1, _swap, identity_b)

    result = _run_cli_verify(log_path)
    assert result.returncode == 1
    output = result.stdout + result.stderr
    assert "subject signature verification failed" in output
    # Sanity: it's the *subject*-sig that fails, not the binding check
    # (since binding now passes after the consistent swap).
    assert "subject identity binding mismatch" not in output


def test_cli_detects_witness_action_in_claim_only(tmp_path: Path) -> None:
    """CLI mirror of test_witness_tamper_action_in_claim_only.

    Mutating only ``subject_claim["action"]`` (leaving entry.action alone)
    invalidates A's signature over the claim bytes. Either the claim
    consistency check or the subject-signature check fires; both indicate
    rejection.
    """
    identity_a, identity_b, _wrapper, log_path = _setup_witness_log(tmp_path)

    def _mutate(entry: dict) -> None:
        entry["subject_claim"] = dict(entry["subject_claim"])
        entry["subject_claim"]["action"] = "evil_action"

    _mutate_and_repair(log_path, 1, _mutate, identity_b)

    result = _run_cli_verify(log_path)
    assert result.returncode == 1
    output = result.stdout + result.stderr
    assert (
        "subject_claim.action" in output
        or "subject signature verification failed" in output
    )


# ---------------------------------------------------------------------------
# Group 7 — regression guard: self entries via append_event omit subject fields
# ---------------------------------------------------------------------------


def test_witness_entry_omits_subject_fields_on_self(tmp_path: Path) -> None:
    """Self entries written via ``append_event`` carry no subject_* fields."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)
    _append_three(wrapper, identity)

    entries = wrapper.read_entries()
    for entry in entries:
        assert entry["kind"] == "self"
        assert "subject_pubkey" not in entry
        assert "subject_claim" not in entry
        assert "subject_signature" not in entry


def test_round_trip_writes_signature_and_pubkey(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    entries = wrapper.read_entries()
    assert len(entries) == 3
    for entry in entries:
        assert "signature" in entry
        assert "reporter_pubkey" in entry
        assert isinstance(entry["signature"], str) and entry["signature"]
        assert isinstance(entry["reporter_pubkey"], str) and entry["reporter_pubkey"]
        # Both must be valid hex.
        bytes.fromhex(entry["signature"])
        bytes.fromhex(entry["reporter_pubkey"])


def test_clean_log_verifies(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    ok, errors = wrapper.verify_integrity()
    assert ok is True
    assert errors == []


def test_content_tamper_detected(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    lines = _load_lines(log_path)
    entry_indices = _entry_line_indices(lines)
    # entry 2 = second appended entry (1-indexed, like verify_integrity).
    second_entry_line = entry_indices[1]
    entry = json.loads(lines[second_entry_line])
    # Mutate details so the recomputed entry_hash will differ.
    entry["details"] = dict(entry.get("details", {}))
    entry["details"]["tampered"] = True
    lines[second_entry_line] = json.dumps(entry) + "\n"
    _dump_lines(log_path, lines)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors
    assert any("2" in err for err in errors)


def test_signature_tamper_detected(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    lines = _load_lines(log_path)
    entry_indices = _entry_line_indices(lines)
    first_entry_line = entry_indices[0]
    entry = json.loads(lines[first_entry_line])
    original_sig = entry["signature"]
    # Replace with all-zero signature of identical hex length.
    entry["signature"] = "00" * (len(original_sig) // 2)
    assert entry["signature"] != original_sig
    lines[first_entry_line] = json.dumps(entry) + "\n"
    _dump_lines(log_path, lines)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors


def test_pubkey_swap_defeated(tmp_path: Path) -> None:
    identity_a = _make_identity(tmp_path, "key_a.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_a, log_path)

    _append_three(wrapper, identity_a)

    identity_b = _make_identity(tmp_path, "key_b.pem")
    assert identity_a.public_key != identity_b.public_key

    lines = _load_lines(log_path)
    entry_indices = _entry_line_indices(lines)
    first_entry_line = entry_indices[0]
    entry = json.loads(lines[first_entry_line])
    entry["reporter_pubkey"] = identity_b.public_key.hex()
    lines[first_entry_line] = json.dumps(entry) + "\n"
    _dump_lines(log_path, lines)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors
    assert any("entry_hash" in err for err in errors)


def test_hash_chain_links_entries(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    entries = wrapper.read_entries()
    assert len(entries) == 3
    assert entries[0]["previous_hash"] == "GENESIS"
    for i in (1, 2):
        assert entries[i]["previous_hash"] == entries[i - 1]["entry_hash"]


def test_empty_log_verifies(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "empty.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    ok, errors = wrapper.verify_integrity()
    assert ok is True
    assert errors == []


def test_identity_used_correctly(tmp_path: Path) -> None:
    identity_a = _make_identity(tmp_path, "key_a.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_a, log_path)

    reporter = str(identity_a.identity_hash)
    for index in range(2):
        wrapper.append_event(
            reporter_id=reporter,
            subject_id=reporter,
            action=f"test_action_{index}",
            details={"index": index},
        )

    entries = wrapper.read_entries()
    assert len(entries) == 2
    expected_pubkey_hex = identity_a.public_key.hex()
    for entry in entries:
        assert entry["reporter_pubkey"] == expected_pubkey_hex


def test_plain_append_log_rejects_signed_entries(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    plain = AppendOnlyLog(log_path)
    ok, errors = plain.verify_integrity()
    assert ok is False
    assert errors


# ---------------------------------------------------------------------------
# Per-check coverage gaps
# ---------------------------------------------------------------------------


def test_pure_chain_only_break(tmp_path: Path) -> None:
    """Mutating entry 2's previous_hash breaks the chain link."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    _mutate_entry(log_path, 2, lambda e: e.update(previous_hash="a" * 64))

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors
    assert any(
        "previous_hash" in err.lower() or "chain" in err.lower()
        for err in errors
    )


def test_pure_entry_hash_mutation(tmp_path: Path) -> None:
    """A mutated entry_hash field surfaces as an entry_hash mismatch."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    _mutate_entry(log_path, 2, lambda e: e.update(entry_hash="f" * 64))

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors
    assert any("entry_hash" in err for err in errors)


def test_real_signature_for_different_message(tmp_path: Path) -> None:
    """A *valid* Ed25519 signature over different bytes must still fail verify."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    # Sign different bytes with the producer's real key — same length, valid hex,
    # valid Ed25519 signature, just over the wrong message.
    forged_sig = identity.sign(b"different message").hex()

    _mutate_entry(log_path, 1, lambda e: e.update(signature=forged_sig))

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors
    # The error must reference signature failure, NOT a length/hex error.
    assert any(
        "signature verification failed" in err.lower()
        or "signature verification error" in err.lower()
        for err in errors
    )
    # And explicitly NOT a length mismatch error (since this signature is the right size).
    assert not any(
        "signature is" in err.lower() and "bytes, expected 64" in err.lower()
        for err in errors
    )


# ---------------------------------------------------------------------------
# Structural tampers
# ---------------------------------------------------------------------------


def test_reordered_entries_detected(tmp_path: Path) -> None:
    """Swapping entries 1 and 2 breaks the chain."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    lines = _load_lines(log_path)
    entry_indices = _entry_line_indices(lines)
    a, b = entry_indices[0], entry_indices[1]
    lines[a], lines[b] = lines[b], lines[a]
    _dump_lines(log_path, lines)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors


def test_deleted_entry_detected(tmp_path: Path) -> None:
    """Deleting entry 2 makes entry 3's previous_hash dangle."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    lines = _load_lines(log_path)
    entry_indices = _entry_line_indices(lines)
    del lines[entry_indices[1]]
    _dump_lines(log_path, lines)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors


def test_duplicated_entry_detected(tmp_path: Path) -> None:
    """A duplicated entry line breaks the chain at the duplicate slot."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    lines = _load_lines(log_path)
    entry_indices = _entry_line_indices(lines)
    second_line = entry_indices[1]
    lines.insert(second_line + 1, lines[second_line])
    _dump_lines(log_path, lines)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors


def test_inserted_fabricated_entry_detected(tmp_path: Path) -> None:
    """An attacker-signed entry inserted mid-chain breaks the chain link.

    Even if the attacker's entry is internally valid (good signature, valid
    identity binding, correct previous_hash pointing at entry 2's stored
    entry_hash), it doesn't match what entry 3 expects as its predecessor,
    so verification fails at entry 4 (the original entry 3).
    """
    identity_a = _make_identity(tmp_path, "key_a.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_a, log_path)

    _append_three(wrapper, identity_a)

    # Build a fabricated entry signed by attacker B over the SAME network.
    identity_b = _make_identity(tmp_path, "key_b.pem")
    lines = _load_lines(log_path)
    entry_indices = _entry_line_indices(lines)
    second_entry = json.loads(lines[entry_indices[1]])

    fabricated = {
        "version": 2,
        "timestamp": "2025-01-01T00:00:00+00:00",
        "reporter_id": str(identity_b.identity_hash),
        "subject_id": str(identity_b.identity_hash),
        "action": "fabricated",
        "severity": 0,
        "details": {"forged": True},
        "evidence": {},
        "details_hash": __import__("hashlib").sha256(
            json.dumps({"forged": True}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "evidence_hash": __import__("hashlib").sha256(
            json.dumps({}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "previous_hash": second_entry["entry_hash"],
        "reporter_pubkey": identity_b.public_key.hex(),
    }
    canonical = json.dumps(
        fabricated, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    fabricated["signature"] = identity_b.sign(canonical).hex()
    hashable = dict(fabricated)
    hashable.pop("entry_hash", None)
    hashable.pop("signature", None)
    fabricated["entry_hash"] = __import__("hashlib").sha256(
        json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    lines.insert(entry_indices[1] + 1, json.dumps(fabricated) + "\n")
    _dump_lines(log_path, lines)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors


# ---------------------------------------------------------------------------
# Field tampering
# ---------------------------------------------------------------------------


def test_tampered_pubkey_size_detected(tmp_path: Path) -> None:
    """Wrong-length reporter_pubkey is rejected with an explicit length error."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    _mutate_entry(log_path, 1, lambda e: e.update(reporter_pubkey="ab" * 30))

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors
    assert any(
        "length" in err.lower() or "pubkey" in err.lower() or "32" in err
        for err in errors
    )


def test_tampered_pubkey_non_hex_detected(tmp_path: Path) -> None:
    """Non-hex reporter_pubkey produces a malformed-hex error."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    _mutate_entry(log_path, 1, lambda e: e.update(reporter_pubkey="zz" * 32))

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors


def test_tampered_signature_length_detected(tmp_path: Path) -> None:
    """Wrong-length signature is rejected explicitly."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    # 62-byte signature (124 hex chars).
    _mutate_entry(log_path, 1, lambda e: e.update(signature="00" * 62))

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors


def test_tampered_timestamp_detected(tmp_path: Path) -> None:
    """Mutating timestamp breaks the entry_hash and the chain."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    _mutate_entry(log_path, 2, lambda e: e.update(timestamp="1970-01-01T00:00:00+00:00"))

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors


def test_missing_signature_field_detected(tmp_path: Path) -> None:
    """Deleting the signature key surfaces a missing-signature error."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    def _drop_sig(entry: dict) -> None:
        entry.pop("signature", None)

    _mutate_entry(log_path, 1, _drop_sig)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors
    assert any("missing signature" in err.lower() for err in errors)


def test_missing_pubkey_field_detected(tmp_path: Path) -> None:
    """Deleting the reporter_pubkey key surfaces a missing-pubkey error."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    def _drop_pk(entry: dict) -> None:
        entry.pop("reporter_pubkey", None)

    _mutate_entry(log_path, 1, _drop_pk)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors
    assert any("missing reporter_pubkey" in err.lower() for err in errors)


def test_pubkey_id_consistent_swap_detected(tmp_path: Path) -> None:
    """A consistent pubkey+id swap to identity B's values still fails verify.

    Even though identity binding now passes (B's id derives from B's pubkey),
    the entry_hash chains in the original pubkey, and the signature was made
    with identity A's secret key — so signature verification fails too.
    """
    identity_a = _make_identity(tmp_path, "key_a.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_a, log_path)

    _append_three(wrapper, identity_a)

    identity_b = _make_identity(tmp_path, "key_b.pem")

    def _swap(entry: dict) -> None:
        entry["reporter_pubkey"] = identity_b.public_key.hex()
        entry["reporter_id"] = str(identity_b.identity_hash)

    _mutate_entry(log_path, 1, _swap)

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors


# ---------------------------------------------------------------------------
# Re-open + persistence
# ---------------------------------------------------------------------------


def test_reopening_existing_log_continues_chain(tmp_path: Path) -> None:
    """Two wrappers sharing a path produce a single contiguous chain."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")

    wrapper_a = SignedAppendOnlyLog(identity, log_path)
    _append_three(wrapper_a, identity)
    del wrapper_a

    wrapper_b = SignedAppendOnlyLog(identity, log_path)
    reporter = str(identity.identity_hash)
    for index in range(2):
        wrapper_b.append_event(
            reporter_id=reporter,
            subject_id=reporter,
            action=f"continued_{index}",
            details={"index": index},
        )

    entries = wrapper_b.read_entries()
    assert len(entries) == 5
    # Entry 4's previous_hash must equal entry 3's entry_hash.
    assert entries[3]["previous_hash"] == entries[2]["entry_hash"]
    assert entries[4]["previous_hash"] == entries[3]["entry_hash"]

    ok, errors = wrapper_b.verify_integrity()
    assert ok is True, errors


# ---------------------------------------------------------------------------
# Severity / evidence
# ---------------------------------------------------------------------------


def test_severity_field_signed(tmp_path: Path) -> None:
    """Severity is preserved verbatim in the entry and verification passes."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    reporter = str(identity.identity_hash)
    wrapper.append_event(
        reporter_id=reporter,
        subject_id=reporter,
        action="severe",
        details={"x": 1},
        severity=5,
    )

    entries = wrapper.read_entries()
    assert len(entries) == 1
    assert entries[0]["severity"] == 5

    ok, errors = wrapper.verify_integrity()
    assert ok is True, errors


def test_evidence_field_signed(tmp_path: Path) -> None:
    """Evidence is preserved verbatim and verification passes."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    reporter = str(identity.identity_hash)
    wrapper.append_event(
        reporter_id=reporter,
        subject_id=reporter,
        action="report",
        details={"x": 1},
        evidence={"forensic": "data"},
    )

    entries = wrapper.read_entries()
    assert len(entries) == 1
    assert entries[0]["evidence"] == {"forensic": "data"}

    ok, errors = wrapper.verify_integrity()
    assert ok is True, errors


# ---------------------------------------------------------------------------
# Payload variety
# ---------------------------------------------------------------------------


def test_empty_details_works(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    reporter = str(identity.identity_hash)
    wrapper.append_event(
        reporter_id=reporter, subject_id=reporter, action="empty", details={}
    )

    entries = wrapper.read_entries()
    assert len(entries) == 1
    assert entries[0]["details"] == {}
    ok, errors = wrapper.verify_integrity()
    assert ok is True, errors


def test_unicode_details_works(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    reporter = str(identity.identity_hash)
    payload = {"key": "héllo wörld 🌍", "中文": "测试"}
    wrapper.append_event(
        reporter_id=reporter, subject_id=reporter, action="unicode", details=payload
    )

    entries = wrapper.read_entries()
    assert len(entries) == 1
    assert entries[0]["details"] == payload
    ok, errors = wrapper.verify_integrity()
    assert ok is True, errors


def test_nested_details_works(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    reporter = str(identity.identity_hash)
    payload = {"nested": {"deep": [1, 2, 3]}}
    wrapper.append_event(
        reporter_id=reporter, subject_id=reporter, action="nested", details=payload
    )

    entries = wrapper.read_entries()
    assert len(entries) == 1
    assert entries[0]["details"] == payload
    ok, errors = wrapper.verify_integrity()
    assert ok is True, errors


def test_none_in_details_works(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    reporter = str(identity.identity_hash)
    payload = {"key": None}
    wrapper.append_event(
        reporter_id=reporter, subject_id=reporter, action="nullish", details=payload
    )

    entries = wrapper.read_entries()
    assert len(entries) == 1
    assert entries[0]["details"] == payload
    ok, errors = wrapper.verify_integrity()
    assert ok is True, errors


# ---------------------------------------------------------------------------
# Constructor input validation
# ---------------------------------------------------------------------------


def test_constructor_rejects_none_identity(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        SignedAppendOnlyLog(None, str(tmp_path / "log.jsonl"))


def test_constructor_rejects_empty_log_path(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    with pytest.raises(ValueError):
        SignedAppendOnlyLog(identity, "")


def test_constructor_accepts_pathlib_path(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path)
    wrapper = SignedAppendOnlyLog(identity, tmp_path / "log.jsonl")

    reporter = str(identity.identity_hash)
    wrapper.append_event(
        reporter_id=reporter,
        subject_id=reporter,
        action="path_ok",
        details={"index": 0},
    )

    entries = wrapper.read_entries()
    assert len(entries) == 1
    ok, errors = wrapper.verify_integrity()
    assert ok is True, errors


# ---------------------------------------------------------------------------
# Other
# ---------------------------------------------------------------------------


def test_pubkey_swap_on_entry_2_detected(tmp_path: Path) -> None:
    """Same as test_pubkey_swap_defeated but mutate entry 2 mid-chain."""
    identity_a = _make_identity(tmp_path, "key_a.pem")
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity_a, log_path)

    _append_three(wrapper, identity_a)

    identity_b = _make_identity(tmp_path, "key_b.pem")

    _mutate_entry(
        log_path,
        2,
        lambda e: e.update(reporter_pubkey=identity_b.public_key.hex()),
    )

    ok, errors = wrapper.verify_integrity()
    assert ok is False
    assert errors


def test_reporter_id_assertion_in_identity_test(tmp_path: Path) -> None:
    """Each entry's reporter_id must equal str(identity.identity_hash)."""
    identity = _make_identity(tmp_path)
    log_path = str(tmp_path / "log.jsonl")
    wrapper = SignedAppendOnlyLog(identity, log_path)

    _append_three(wrapper, identity)

    expected_id = str(identity.identity_hash)
    entries = wrapper.read_entries()
    assert len(entries) == 3
    for entry in entries:
        assert entry["reporter_id"] == expected_id
