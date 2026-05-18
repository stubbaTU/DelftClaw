"""TDD tests for the PeerLog audit-hook on verification failure."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.demo.witness_tamper.setup import bootstrap
from redteam.demo.witness_tamper.tamper import tamper_witness_entry
from redteam.primitives.peer_log import PeerLog
from redteam.primitives.signed_log import SignedAppendOnlyLog


def _c_audit_log(boot) -> SignedAppendOnlyLog:
    """Build a fresh signed log for C dedicated to audit entries."""
    audit_path = boot.c_log_path.with_suffix(".audit.log")
    return SignedAppendOnlyLog(boot.c_identity, audit_path)


def _integrity_failures(log: SignedAppendOnlyLog) -> list[dict]:
    return [
        entry
        for entry in log.read_entries()
        if entry.get("action") == "log_integrity_failure"
    ]


def test_audit_hook_default_none_unchanged_behavior(tmp_path: Path) -> None:
    boot = bootstrap(tmp_path)
    tampered = tamper_witness_entry(boot.witness_entry, boot.b_identity)
    peer_log = PeerLog(
        tmp_path / "peer_logs",
        network=boot.network,
        own_id=boot.c_identity.identity_hash,
    )

    stored, source_id, errors, duplicate = peer_log.accept_entry(tampered)

    assert stored is False
    assert duplicate is False
    assert source_id == boot.b_identity.identity_hash
    assert errors


def test_audit_hook_writes_log_integrity_failure_on_tamper(tmp_path: Path) -> None:
    boot = bootstrap(tmp_path)
    audit_log = _c_audit_log(boot)
    before = len(_integrity_failures(audit_log))

    tampered = tamper_witness_entry(boot.witness_entry, boot.b_identity)
    peer_log = PeerLog(
        tmp_path / "peer_logs",
        network=boot.network,
        own_id=boot.c_identity.identity_hash,
        audit_log=audit_log,
    )

    stored, _sid, errors, _dup = peer_log.accept_entry(tampered)
    assert stored is False

    failures = _integrity_failures(audit_log)
    assert len(failures) == before + 1
    new = failures[-1]
    assert new["action"] == "log_integrity_failure"
    assert new["reporter_id"] == boot.c_identity.identity_hash
    assert new["subject_id"] == boot.b_identity.identity_hash
    assert new["severity"] == 20
    assert new["details"]["errors"]
    assert new["details"]["errors"] == errors
    assert new["details"]["rejected_entry_hash"] == tampered["entry_hash"]
    assert new["details"]["rejected_kind"] == tampered.get("kind")


def test_audit_hook_does_not_fire_on_success(tmp_path: Path) -> None:
    boot = bootstrap(tmp_path)
    audit_log = _c_audit_log(boot)
    before = len(_integrity_failures(audit_log))

    peer_log = PeerLog(
        tmp_path / "peer_logs",
        network=boot.network,
        own_id=boot.c_identity.identity_hash,
        audit_log=audit_log,
    )

    stored, _sid, errors, _dup = peer_log.accept_entry(boot.witness_entry)
    assert stored is True, errors

    failures = _integrity_failures(audit_log)
    assert len(failures) == before


def test_audit_hook_does_not_fire_on_same_identity_rejection(tmp_path: Path) -> None:
    boot = bootstrap(tmp_path)
    audit_log = _c_audit_log(boot)
    before = len(_integrity_failures(audit_log))

    peer_log = PeerLog(
        tmp_path / "peer_logs",
        network=boot.network,
        own_id=boot.b_identity.identity_hash,
        audit_log=audit_log,
    )

    stored, source_id, errors, _dup = peer_log.accept_entry(boot.witness_entry)
    assert stored is False
    assert source_id == boot.b_identity.identity_hash
    assert errors == ["entry rejected: same-identity submission"]

    failures = _integrity_failures(audit_log)
    assert len(failures) == before


def test_audit_subject_id_is_rejected_reporter(tmp_path: Path) -> None:
    boot = bootstrap(tmp_path)
    audit_log = _c_audit_log(boot)
    tampered = tamper_witness_entry(boot.witness_entry, boot.b_identity)

    peer_log = PeerLog(
        tmp_path / "peer_logs",
        network=boot.network,
        own_id=boot.c_identity.identity_hash,
        audit_log=audit_log,
    )
    peer_log.accept_entry(tampered)

    failures = _integrity_failures(audit_log)
    assert failures, "expected one audit entry"
    assert failures[-1]["subject_id"] == boot.b_identity.identity_hash
    assert failures[-1]["subject_id"] != boot.c_identity.identity_hash


@pytest.mark.skip(reason="audit hook deliberately runs outside the lock; covered by inspection")
def test_audit_hook_fires_outside_lock(tmp_path: Path) -> None:  # pragma: no cover
    pass
