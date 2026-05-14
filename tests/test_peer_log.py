"""TDD red-step tests for ``PeerLog``.

These tests intentionally fail until ``redteam.primitives.peer_log`` is
implemented and ``SignedAppendOnlyLog.verify_foreign_entry`` exists. They
cover the per-source jsonl storage layout, accept/reject paths for the
isolated-entry verification, idempotency, multi-source separation, the
read API, the same-identity downgrade defense, and concurrent appends to
the same source.

API under test (per
``C:\\Users\\lucas\\.claude\\plans\\yes-and-i-snug-bengio.md``):

    PeerLog(peer_log_dir, network: str, own_id: str | None = None)
    PeerLog.accept_entry(entry) -> tuple[bool, str | None, list[str], bool]
        # (stored, source_id, errors, duplicate)
    PeerLog.read_entries_for(source_id) -> list[dict]
    PeerLog.list_sources() -> list[str]

Storage: ``<peer_log_dir>/<source_id>.jsonl``, one entry per line,
append-only, no header.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

import pytest

from identity.agent_identity import AgentIdentity
from identity.seed import KeyfileSeedSource
from redteam.primitives.signed_log import SignedAppendOnlyLog

# This import will fail in the red phase — PeerLog does not exist yet.
from redteam.primitives.peer_log import PeerLog  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers (mirrors test_signed_log.py conventions; private, top of file)
# ---------------------------------------------------------------------------


def _make_identity(
    tmp_path: Path,
    name: str = "test_key.pem",
    network: str = "MAINNET",
) -> AgentIdentity:
    """Create a fresh AgentIdentity backed by a seed file in tmp_path."""
    seed = KeyfileSeedSource(str(tmp_path / name)).load()
    return AgentIdentity.from_seed(seed, network=network)


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _stable_hash_hex(payload: dict) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _make_subject_claim(
    identity: AgentIdentity,
    action: str,
    details: dict,
    *,
    claim_timestamp: str = "2025-01-01T00:00:00+00:00",
    nonce_hex: str = "00112233445566778899aabbccddeeff",
) -> tuple[dict, bytes, bytes]:
    """Build and Ed25519-sign a deterministic claim envelope."""
    claim = {
        "kind": "claim",
        "version": 1,
        "subject_id": str(identity.network_hash),
        "action": action,
        "details_hash": _stable_hash_hex(details),
        "claim_timestamp": claim_timestamp,
        "nonce": nonce_hex,
    }
    sig = identity.ipv8.sign(_canonical(claim))
    return claim, identity.ipv8.raw_pubkey, sig


def _recompute_reporter_sig_and_hash(
    entry: dict, identity: AgentIdentity
) -> dict:
    """Re-sign + re-hash so the entry's chain hash is internally consistent.

    Used after mutating a foreign entry to test that ``verify_foreign_entry``
    still rejects it on the remaining check that should fire.
    """
    payload = dict(entry)
    payload.pop("entry_hash", None)
    payload.pop("signature", None)
    sig = identity.ipv8.sign(_canonical(payload)).hex()
    entry["signature"] = sig
    hashable = dict(entry)
    hashable.pop("entry_hash", None)
    hashable.pop("signature", None)
    entry["entry_hash"] = hashlib.sha256(_canonical(hashable)).hexdigest()
    return entry


def _foreign_self_entry(
    tmp_path: Path,
    *,
    name: str = "foreign_key.pem",
    network: str = "MAINNET",
    action: str = "foreign_action",
    details: dict | None = None,
) -> tuple[AgentIdentity, dict]:
    """Create a foreign identity + log, append one self entry, return entry dict."""
    identity = _make_identity(tmp_path, name, network=network)
    log_path = str(tmp_path / f"{name}.log")
    wrapper = SignedAppendOnlyLog(identity, log_path)
    wrapper.append_event(
        reporter_id=str(identity.network_hash),
        subject_id=str(identity.network_hash),
        action=action,
        details=details if details is not None else {"k": "v"},
    )
    entries = wrapper.read_entries()
    assert len(entries) == 1
    return identity, entries[0]


def _foreign_witness_entry(
    tmp_path: Path,
    *,
    reporter_name: str = "foreign_reporter.pem",
    subject_name: str = "foreign_subject.pem",
    network: str = "MAINNET",
    action: str = "observed_action",
    details: dict | None = None,
    nonce_hex: str = "55" * 16,
) -> tuple[AgentIdentity, AgentIdentity, dict]:
    """Create two foreign identities, append a witness entry, return entry dict."""
    subject = _make_identity(tmp_path, subject_name, network=network)
    reporter = _make_identity(tmp_path, reporter_name, network=network)

    if details is None:
        details = {"k": "v"}
    claim, pk, sig = _make_subject_claim(
        subject, action, details, nonce_hex=nonce_hex
    )
    log_path = str(tmp_path / f"{reporter_name}.log")
    wrapper = SignedAppendOnlyLog(reporter, log_path)
    wrapper.append_witness_event(
        reporter_id=str(reporter.network_hash),
        subject_id=str(subject.network_hash),
        subject_pubkey=pk,
        subject_claim=claim,
        subject_signature=sig,
        action=action,
        details=details,
    )
    entries = wrapper.read_entries()
    assert len(entries) == 1
    return subject, reporter, entries[0]


# ---------------------------------------------------------------------------
# Empty / construction
# ---------------------------------------------------------------------------


def test_empty_peer_log_lists_no_sources(tmp_path: Path) -> None:
    """A fresh PeerLog dir reports no known sources."""
    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(str(peer_log_dir), network="MAINNET")
    assert peer_log.list_sources() == []


# ---------------------------------------------------------------------------
# Accept — happy paths
# ---------------------------------------------------------------------------


def test_accept_valid_self_entry_from_other_identity_stores(tmp_path: Path) -> None:
    """A valid self entry from a different identity is accepted and stored."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, source_id, errors, duplicate = peer_log.accept_entry(entry)

    assert stored is True, errors
    assert errors == []
    assert duplicate is False
    assert source_id == str(foreign_identity.network_hash)


def test_accept_valid_witness_entry_from_other_identity_stores(tmp_path: Path) -> None:
    """A valid witness entry from a different reporter is accepted and stored."""
    own = _make_identity(tmp_path, "own.pem")
    _, reporter, entry = _foreign_witness_entry(tmp_path)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, source_id, errors, duplicate = peer_log.accept_entry(entry)

    assert stored is True, errors
    assert errors == []
    assert duplicate is False
    assert source_id == str(reporter.network_hash)


def test_accept_writes_one_jsonl_line_per_entry(tmp_path: Path) -> None:
    """Accepted entries are appended one-per-line to the per-source file."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, source_id, _errors, _dup = peer_log.accept_entry(entry)
    assert stored is True

    source_file = peer_log_dir / f"{source_id}.jsonl"
    text = source_file.read_text(encoding="utf-8")
    # Exactly one non-empty line.
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    # Compare a stable subset rather than full dict equality — keeps the
    # test honest if a future change adds an envelope-level field on the
    # wire (e.g. ``received_at``).
    for field in ("entry_hash", "signature", "reporter_id", "kind", "action"):
        assert parsed[field] == entry[field], field


def test_accept_creates_per_source_file_named_by_reporter_id(tmp_path: Path) -> None:
    """The on-disk file is named ``<reporter_id>.jsonl`` and lives in peer_log_dir."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    peer_log.accept_entry(entry)

    expected = peer_log_dir / f"{foreign_identity.network_hash}.jsonl"
    assert expected.exists()


def test_accept_returns_correct_source_id(tmp_path: Path) -> None:
    """``source_id`` returned is the foreign entry's reporter_id."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)

    peer_log = PeerLog(
        str(tmp_path / "peer_logs"),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    _stored, source_id, _errors, _dup = peer_log.accept_entry(entry)
    assert source_id == entry["reporter_id"]
    assert source_id == str(foreign_identity.network_hash)


# ---------------------------------------------------------------------------
# Accept — rejection paths (parametrized tampers)
# ---------------------------------------------------------------------------


def test_accept_rejects_malformed_entry_missing_pubkey(tmp_path: Path) -> None:
    """Removing reporter_pubkey makes the entry unverifiable; reject."""
    own = _make_identity(tmp_path, "own.pem")
    _, entry = _foreign_self_entry(tmp_path)
    entry.pop("reporter_pubkey", None)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, source_id, errors, duplicate = peer_log.accept_entry(entry)

    assert stored is False
    assert duplicate is False
    assert errors  # non-empty
    # No file should be created on a rejected entry.
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_bad_signature(tmp_path: Path) -> None:
    """A zeroed signature must fail Ed25519 verify and be rejected."""
    own = _make_identity(tmp_path, "own.pem")
    _, entry = _foreign_self_entry(tmp_path)
    # Zero the signature in-place; entry_hash will then mismatch too, but
    # both surface as errors and the entry is rejected.
    entry["signature"] = "00" * 64

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _source_id, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_wrong_identity_binding(tmp_path: Path) -> None:
    """Mutating reporter_id breaks SHA256(pubkey || network) == reporter_id."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)
    # Replace reporter_id with a fake hash; recompute reporter sig + entry_hash
    # so signature/hash checks pass and only the binding check fires.
    entry["reporter_id"] = "f" * 64
    _recompute_reporter_sig_and_hash(entry, foreign_identity)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _source_id, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_unsupported_version(tmp_path: Path) -> None:
    """Only version == 2 is accepted."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)
    entry["version"] = 1
    _recompute_reporter_sig_and_hash(entry, foreign_identity)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _source_id, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_cross_network_entry(tmp_path: Path) -> None:
    """A foreign entry produced under TESTNET is rejected by a MAINNET PeerLog."""
    own = _make_identity(tmp_path, "own.pem")
    # Build a foreign entry whose identity_hash bound to TESTNET.
    _, entry = _foreign_self_entry(tmp_path, name="tnet.pem", network="TESTNET")

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _source_id, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_same_identity_submission(tmp_path: Path) -> None:
    """Reject entries whose reporter_id equals the receiver's own_id."""
    own = _make_identity(tmp_path, "own.pem")
    # Build an entry signed by own — reuse the helper but with the SAME key
    # path the receiver uses.
    own_log = str(tmp_path / "own.log")
    wrapper = SignedAppendOnlyLog(own, own_log)
    wrapper.append_event(
        reporter_id=str(own.network_hash),
        subject_id=str(own.network_hash),
        action="self_action",
        details={"a": 1},
    )
    entry = wrapper.read_entries()[0]

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _source_id, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    # No file under our own id.
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


@pytest.mark.parametrize(
    "tamper",
    [
        # Mutate reporter_pubkey hex (still 32 bytes, but wrong key).
        "swap_pubkey",
        # Mutate the embedded action — invalidates the reporter signature.
        "swap_action",
        # Mutate the recorded details — details_hash won't match either.
        "swap_details",
        # Replace signature with valid-shape 64 bytes but wrong sig.
        "swap_signature",
        # Single-bit flip in entry_hash hex.
        "swap_entry_hash",
    ],
)
def test_accept_rejects_post_signing_tamper_axes(
    tmp_path: Path, tamper: str
) -> None:
    """Tamper with one field after signing; verify_foreign_entry must reject."""
    own = _make_identity(tmp_path, "own.pem")
    _, entry = _foreign_self_entry(tmp_path)

    if tamper == "swap_pubkey":
        # Replace reporter_pubkey with another valid 32-byte pubkey. Reporter
        # signature now fails (was signed by original key).
        other = _make_identity(tmp_path, "tamper_other.pem")
        entry["reporter_pubkey"] = other.ipv8.raw_pubkey.hex()
    elif tamper == "swap_action":
        entry["action"] = "evil_action"
    elif tamper == "swap_details":
        entry["details"] = {"evil": True}
    elif tamper == "swap_signature":
        # Valid-shape 64 bytes, but not a real Ed25519 signature for this
        # entry. Catches signatures-substitution attacks separately from
        # length/hex errors.
        entry["signature"] = ("42" * 64)
    elif tamper == "swap_entry_hash":
        h = entry["entry_hash"]
        entry["entry_hash"] = ("1" if h[0] == "0" else "0") + h[1:]
    else:  # pragma: no cover
        pytest.fail(f"unknown tamper: {tamper}")

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _source_id, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False, f"tamper {tamper} should reject"
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


# ---------------------------------------------------------------------------
# Accept — witness-specific rejections
# ---------------------------------------------------------------------------


def test_accept_rejects_witness_with_invalid_subject_signature(tmp_path: Path) -> None:
    """Witness entry with zeroed subject_signature is rejected."""
    own = _make_identity(tmp_path, "own.pem")
    _, reporter, entry = _foreign_witness_entry(tmp_path)
    entry["subject_signature"] = "00" * 64
    # Re-fix reporter sig + entry_hash so chain checks pass; only subject sig
    # check should fire.
    _recompute_reporter_sig_and_hash(entry, reporter)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _source_id, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_witness_with_subject_id_mismatch(tmp_path: Path) -> None:
    """Witness entry where subject_id does not derive from subject_pubkey is rejected."""
    own = _make_identity(tmp_path, "own.pem")
    _, reporter, entry = _foreign_witness_entry(tmp_path)
    entry["subject_id"] = "f" * 64
    _recompute_reporter_sig_and_hash(entry, reporter)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _source_id, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_self_entry_smuggling_subject_fields(tmp_path: Path) -> None:
    """Downgrade defense: self entry must not carry witness-only fields."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)
    # Smuggle witness-only fields into a self entry.
    entry["subject_pubkey"] = "aa" * 32
    entry["subject_signature"] = "bb" * 64
    entry["subject_claim"] = {"smuggled": True}
    _recompute_reporter_sig_and_hash(entry, foreign_identity)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _source_id, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_accept_idempotent_on_duplicate_returns_duplicate_true(tmp_path: Path) -> None:
    """Re-accepting the same entry returns duplicate=True, stored=False, no rewrite."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )

    # First call — stored.
    stored1, source_id1, errors1, duplicate1 = peer_log.accept_entry(entry)
    assert stored1 is True, errors1
    assert duplicate1 is False

    source_file = peer_log_dir / f"{source_id1}.jsonl"
    first_size = source_file.stat().st_size

    # Second call with the SAME entry — duplicate, not stored.
    stored2, source_id2, errors2, duplicate2 = peer_log.accept_entry(entry)
    assert stored2 is False
    assert duplicate2 is True
    assert errors2 == []
    assert source_id2 == source_id1

    # File on disk is unchanged.
    assert source_file.stat().st_size == first_size


# ---------------------------------------------------------------------------
# Multi-source separation
# ---------------------------------------------------------------------------


def test_accept_two_distinct_sources_creates_two_files(tmp_path: Path) -> None:
    """Two foreign entries from two different identities → two separate files."""
    own = _make_identity(tmp_path, "own.pem")
    id1, entry1 = _foreign_self_entry(tmp_path, name="src1.pem")
    id2, entry2 = _foreign_self_entry(tmp_path, name="src2.pem", action="other")

    assert id1.network_hash != id2.network_hash

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    s1, sid1, e1, d1 = peer_log.accept_entry(entry1)
    s2, sid2, e2, d2 = peer_log.accept_entry(entry2)

    assert s1 is True and s2 is True
    assert sid1 != sid2
    assert (peer_log_dir / f"{sid1}.jsonl").exists()
    assert (peer_log_dir / f"{sid2}.jsonl").exists()


# ---------------------------------------------------------------------------
# Read API
# ---------------------------------------------------------------------------


def test_read_entries_for_returns_in_insertion_order(tmp_path: Path) -> None:
    """``read_entries_for`` returns entries in the order they were accepted."""
    own = _make_identity(tmp_path, "own.pem")
    # Build three entries from the same foreign identity.
    foreign = _make_identity(tmp_path, "src.pem")
    log_path = str(tmp_path / "src.log")
    wrapper = SignedAppendOnlyLog(foreign, log_path)
    for index in range(3):
        wrapper.append_event(
            reporter_id=str(foreign.network_hash),
            subject_id=str(foreign.network_hash),
            action=f"action_{index}",
            details={"i": index},
        )
    entries = wrapper.read_entries()
    assert len(entries) == 3

    peer_log = PeerLog(
        str(tmp_path / "peer_logs"),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    for entry in entries:
        stored, _sid, errs, _dup = peer_log.accept_entry(entry)
        assert stored is True, errs

    out = peer_log.read_entries_for(str(foreign.network_hash))
    assert out == entries


def test_read_entries_for_unknown_source_returns_empty(tmp_path: Path) -> None:
    """Reading entries for an unknown source_id returns []."""
    peer_log = PeerLog(str(tmp_path / "peer_logs"), network="MAINNET")
    assert peer_log.read_entries_for("a" * 64) == []


def test_list_sources_returns_all_known(tmp_path: Path) -> None:
    """``list_sources`` returns every reporter_id that has a stored entry."""
    own = _make_identity(tmp_path, "own.pem")
    id1, entry1 = _foreign_self_entry(tmp_path, name="src1.pem")
    id2, entry2 = _foreign_self_entry(tmp_path, name="src2.pem", action="other")

    peer_log = PeerLog(
        str(tmp_path / "peer_logs"),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    peer_log.accept_entry(entry1)
    peer_log.accept_entry(entry2)

    sources = set(peer_log.list_sources())
    assert sources == {str(id1.network_hash), str(id2.network_hash)}


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_concurrent_accept_two_threads_same_source_both_succeed(tmp_path: Path) -> None:
    """Two threads accepting different entries from the same source both succeed.

    Barrier-synced to maximise overlap. Final file must contain both entries
    on separate lines and be parseable JSONL — i.e. the lock + flush + fsync
    write path is collision-free.
    """
    own = _make_identity(tmp_path, "own.pem")
    foreign = _make_identity(tmp_path, "src.pem")
    log_path = str(tmp_path / "src.log")
    wrapper = SignedAppendOnlyLog(foreign, log_path)

    wrapper.append_event(
        reporter_id=str(foreign.network_hash),
        subject_id=str(foreign.network_hash),
        action="a1",
        details={"i": 1},
    )
    wrapper.append_event(
        reporter_id=str(foreign.network_hash),
        subject_id=str(foreign.network_hash),
        action="a2",
        details={"i": 2},
    )
    entries = wrapper.read_entries()
    assert len(entries) == 2

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )

    barrier = threading.Barrier(2)
    results: list[tuple[bool, list[str], bool] | None] = [None, None]
    exceptions: list[BaseException | None] = [None, None]

    def _worker(idx: int, entry: dict) -> None:
        try:
            barrier.wait()
            stored, _sid, errs, dup = peer_log.accept_entry(entry)
            results[idx] = (stored, errs, dup)
        except BaseException as exc:  # capture, surface in main thread
            exceptions[idx] = exc

    t1 = threading.Thread(target=_worker, args=(0, entries[0]))
    t2 = threading.Thread(target=_worker, args=(1, entries[1]))
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)
    assert not t1.is_alive() and not t2.is_alive()

    # Surface any worker-thread exception explicitly — a silent
    # ``results[i] is None`` would otherwise mask a thrown error.
    assert exceptions == [None, None], exceptions
    assert results[0] is not None and results[1] is not None
    stored0, errs0, dup0 = results[0]
    stored1, errs1, dup1 = results[1]
    assert stored0 is True, errs0
    assert stored1 is True, errs1
    assert dup0 is False and dup1 is False

    source_file = peer_log_dir / f"{foreign.network_hash}.jsonl"
    text = source_file.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    # Both entries are present (order is not guaranteed under concurrency).
    assert {p["entry_hash"] for p in parsed} == {
        entries[0]["entry_hash"],
        entries[1]["entry_hash"],
    }


# ---------------------------------------------------------------------------
# Pydantic-shape adjacent rejections (matches server-side T-1 mirrors)
# ---------------------------------------------------------------------------


def test_accept_rejects_unknown_kind(tmp_path: Path) -> None:
    """``kind="delegate"`` is outside the {self, witness} discriminator."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)
    entry["kind"] = "delegate"
    _recompute_reporter_sig_and_hash(entry, foreign_identity)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _sid, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_missing_entry_hash(tmp_path: Path) -> None:
    """A foreign entry missing entry_hash is rejected."""
    own = _make_identity(tmp_path, "own.pem")
    _, entry = _foreign_self_entry(tmp_path)
    entry.pop("entry_hash", None)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _sid, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_missing_version(tmp_path: Path) -> None:
    """A foreign entry missing ``version`` is rejected."""
    own = _make_identity(tmp_path, "own.pem")
    _, entry = _foreign_self_entry(tmp_path)
    entry.pop("version", None)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _sid, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors


# ---------------------------------------------------------------------------
# Construction / directory handling
# ---------------------------------------------------------------------------


def test_peer_log_dir_created_if_missing(tmp_path: Path) -> None:
    """Constructor creates a missing peer_log_dir; first accept stores normally."""
    own = _make_identity(tmp_path, "own.pem")
    _, entry = _foreign_self_entry(tmp_path)

    # Path that doesn't exist yet — and has a missing parent.
    peer_log_dir = tmp_path / "nested" / "peer_logs"
    assert not peer_log_dir.exists()

    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    assert peer_log_dir.exists() and peer_log_dir.is_dir()

    stored, _sid, errs, _dup = peer_log.accept_entry(entry)
    assert stored is True, errs
    assert (peer_log_dir / f"{entry['reporter_id']}.jsonl").exists()


def test_peer_log_rejects_path_pointing_to_file(tmp_path: Path) -> None:
    """If peer_log_dir points to a file, construction raises."""
    file_path = tmp_path / "f.txt"
    file_path.write_text("not a directory", encoding="utf-8")
    with pytest.raises((NotADirectoryError, ValueError, FileExistsError)):
        PeerLog(str(file_path), network="MAINNET")


# ---------------------------------------------------------------------------
# Witness-specific rejections — additional axes
# ---------------------------------------------------------------------------


def test_accept_rejects_witness_with_subject_pubkey_length_mismatch(
    tmp_path: Path,
) -> None:
    """Witness entry with a subject_pubkey shorter than 32 bytes is rejected."""
    own = _make_identity(tmp_path, "own.pem")
    _, reporter, entry = _foreign_witness_entry(tmp_path)
    entry["subject_pubkey"] = ("aa" * 31)
    _recompute_reporter_sig_and_hash(entry, reporter)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _sid, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_witness_with_subject_signature_length_mismatch(
    tmp_path: Path,
) -> None:
    """Witness entry with a subject_signature shorter than 64 bytes is rejected."""
    own = _make_identity(tmp_path, "own.pem")
    _, reporter, entry = _foreign_witness_entry(tmp_path)
    entry["subject_signature"] = ("aa" * 63)
    _recompute_reporter_sig_and_hash(entry, reporter)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _sid, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_witness_with_inconsistent_action(tmp_path: Path) -> None:
    """Mutating only entry.action (not claim.action) breaks claim consistency."""
    own = _make_identity(tmp_path, "own.pem")
    _, reporter, entry = _foreign_witness_entry(tmp_path)
    entry["action"] = "evil_action"
    _recompute_reporter_sig_and_hash(entry, reporter)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _sid, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_rejects_witness_with_inconsistent_details_hash(
    tmp_path: Path,
) -> None:
    """Mutating details_hash in the entry breaks claim consistency."""
    own = _make_identity(tmp_path, "own.pem")
    _, reporter, entry = _foreign_witness_entry(tmp_path)
    entry["details_hash"] = "f" * 64
    _recompute_reporter_sig_and_hash(entry, reporter)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _sid, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


def test_accept_witness_where_subject_equals_receiver_stored(tmp_path: Path) -> None:
    """Witness-of-self is accountability data — receiver caches it.

    The receiver should know what other peers claim about it. The
    same-identity guard fires only on ``reporter_id == own_id``, not on
    ``subject_id``.
    """
    own = _make_identity(tmp_path, "own.pem")
    # A foreign reporter (not own) signs a witness entry whose subject is
    # ``own``. ``own`` must sign the claim — so reuse own's identity to
    # build the claim envelope.
    reporter = _make_identity(tmp_path, "fr.pem")
    details = {"k": "v"}
    claim, pk, sig = _make_subject_claim(
        own, "obs", details, nonce_hex="aa" * 16
    )
    log_path = str(tmp_path / "fr.log")
    wrapper = SignedAppendOnlyLog(reporter, log_path)
    wrapper.append_witness_event(
        reporter_id=str(reporter.network_hash),
        subject_id=str(own.network_hash),
        subject_pubkey=pk,
        subject_claim=claim,
        subject_signature=sig,
        action="obs",
        details=details,
    )
    entry = wrapper.read_entries()[0]

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, source_id, errors, _dup = peer_log.accept_entry(entry)
    assert stored is True, errors
    assert source_id == str(reporter.network_hash)
    assert (peer_log_dir / f"{reporter.network_hash}.jsonl").exists()


def test_accept_rejects_uppercase_reporter_id(tmp_path: Path) -> None:
    """Uppercased reporter_id breaks the SHA256-hexdigest binding (lowercase canonical)."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)
    entry["reporter_id"] = entry["reporter_id"].upper()
    _recompute_reporter_sig_and_hash(entry, foreign_identity)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    stored, _sid, errors, _dup = peer_log.accept_entry(entry)

    assert stored is False
    assert errors
    assert (not peer_log_dir.exists()) or list(peer_log_dir.glob("*.jsonl")) == []


# ---------------------------------------------------------------------------
# Resilience: corrupt files, ignore non-jsonl files
# ---------------------------------------------------------------------------


def test_accept_handles_corrupt_jsonl_line_in_existing_file(tmp_path: Path) -> None:
    """A non-JSON line in the per-source file is skipped on dedup scan."""
    own = _make_identity(tmp_path, "own.pem")
    foreign_identity, entry = _foreign_self_entry(tmp_path)

    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )

    # Pre-write a corrupt line under the source's filename. The dir now
    # exists (PeerLog.__init__ creates it).
    source_id = entry["reporter_id"]
    source_file = peer_log_dir / f"{source_id}.jsonl"
    source_file.write_text("this is not json\n", encoding="utf-8")

    stored, sid, errors, dup = peer_log.accept_entry(entry)
    assert stored is True, errors
    assert dup is False
    assert sid == source_id
    # File now contains the corrupt line plus our entry.
    text = source_file.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 2


def test_list_sources_ignores_non_jsonl_files(tmp_path: Path) -> None:
    """``list_sources`` returns only ``*.jsonl`` filename stems, not unrelated files."""
    own = _make_identity(tmp_path, "own.pem")
    peer_log_dir = tmp_path / "peer_logs"
    peer_log = PeerLog(
        str(peer_log_dir),
        network="MAINNET",
        own_id=str(own.network_hash),
    )
    # Pre-write a .txt file in the dir.
    (peer_log_dir / "stray.txt").write_text("not a peer file", encoding="utf-8")

    # And accept one valid entry so we have at least one .jsonl entry too.
    foreign_identity, entry = _foreign_self_entry(tmp_path)
    stored, _sid, errs, _dup = peer_log.accept_entry(entry)
    assert stored, errs

    sources = peer_log.list_sources()
    assert "stray" not in sources
    assert str(foreign_identity.network_hash) in sources
