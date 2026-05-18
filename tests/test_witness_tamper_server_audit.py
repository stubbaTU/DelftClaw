"""TDD tests for ``build_app(enable_integrity_audit=...)`` plumbing.

When enabled, the server's own ``SignedAppendOnlyLog`` (the auditor's log
in our threat model) is wired into the ``PeerLog`` as ``audit_log``, so a
foreign-entry verification failure writes a ``log_integrity_failure``
self-entry against the rejected entry's reporter.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from fastapi.testclient import TestClient

from redteam.demo.witness_tamper.setup import bootstrap
from redteam.demo.witness_tamper.tamper import tamper_witness_entry
from redteam.integration.server import build_app
from redteam.primitives.signed_log import SignedAppendOnlyLog


def _read_failures(identity, log_path: Path) -> list[dict]:
    log = SignedAppendOnlyLog(identity, log_path)
    return [
        entry
        for entry in log.read_entries()
        if entry.get("action") == "log_integrity_failure"
    ]


def test_build_app_default_no_audit(tmp_path: Path) -> None:
    boot = bootstrap(tmp_path)
    before = len(_read_failures(boot.c_identity, boot.c_log_path))

    app = build_app(
        boot.c_identity,
        boot.c_log_path,
        peer_log_dir=str(tmp_path / "peer_logs"),
    )
    tampered = tamper_witness_entry(boot.witness_entry, boot.b_identity)

    with TestClient(app) as client:
        resp = client.post("/entries", json=tampered)
    assert resp.status_code == 400
    assert resp.json()["error"] == "foreign entry verification failed"

    after = len(_read_failures(boot.c_identity, boot.c_log_path))
    assert after == before


def test_build_app_with_audit_enabled_writes_log_integrity_failure(
    tmp_path: Path,
) -> None:
    boot = bootstrap(tmp_path)
    before = len(_read_failures(boot.c_identity, boot.c_log_path))

    app = build_app(
        boot.c_identity,
        boot.c_log_path,
        peer_log_dir=str(tmp_path / "peer_logs"),
        enable_integrity_audit=True,
    )
    tampered = tamper_witness_entry(boot.witness_entry, boot.b_identity)

    with TestClient(app) as client:
        resp = client.post("/entries", json=tampered)
    assert resp.status_code == 400

    failures = _read_failures(boot.c_identity, boot.c_log_path)
    assert len(failures) == before + 1
    new = failures[-1]
    assert new["action"] == "log_integrity_failure"
    assert new["subject_id"] == boot.b_identity.identity_hash
    assert new["severity"] == 20
    assert new["details"]["errors"]
    assert new["details"]["rejected_entry_hash"] == tampered["entry_hash"]


def test_build_app_with_audit_accepted_entry_no_audit_write(
    tmp_path: Path,
) -> None:
    boot = bootstrap(tmp_path)
    before = len(_read_failures(boot.c_identity, boot.c_log_path))

    app = build_app(
        boot.c_identity,
        boot.c_log_path,
        peer_log_dir=str(tmp_path / "peer_logs"),
        enable_integrity_audit=True,
    )

    with TestClient(app) as client:
        resp = client.post("/entries", json=boot.witness_entry)
    assert resp.status_code == 200, resp.text

    after = _read_failures(boot.c_identity, boot.c_log_path)
    assert len(after) == before


def test_build_app_audit_default_false_signature_backcompat() -> None:
    sig = inspect.signature(build_app)
    assert "enable_integrity_audit" in sig.parameters
    assert sig.parameters["enable_integrity_audit"].default is False
