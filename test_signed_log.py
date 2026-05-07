"""TDD red-step tests for SignedAppendOnlyLog.

These tests intentionally fail until ``redteam.primitives.signed_log`` is
implemented. They exercise the sign-then-chain append flow, tamper
detection (content, signature, public-key swap), the hash chain
invariants, the empty-log case, and document the wrinkle that the plain
``AppendOnlyLog`` does not understand signed entries.
"""

from __future__ import annotations

import json
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
