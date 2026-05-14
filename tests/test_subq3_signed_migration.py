"""Red-step TDD tests for Phase D subq3 integrity migration.

These tests assert that ``HostLogService``, ``LogTamperSuite``, and
``run_log_integrity_experiment`` write and verify signed log entries —
i.e. that they have been migrated off the unsigned ``AppendOnlyLog``
onto ``SignedAppendOnlyLog``. They are expected to FAIL until the Green
step of Phase D is implemented.

Each test uses ``tmp_path`` for both the identity key file and the log
file to avoid polluting the repo root.
"""

from __future__ import annotations

from pathlib import Path

from identity.openclaw_identity import OpenClawIdentity
from redteam.primitives.signed_log import SignedAppendOnlyLog
from security.subq3_integrity.integrity import (
    HostLogService,
    LogTamperSuite,
    run_log_integrity_experiment,
)


def _make_identity(tmp_path: Path, name: str = "id.json") -> OpenClawIdentity:
    return OpenClawIdentity(network="MAINNET", key_path=str(tmp_path / name))


def test_host_log_service_uses_signed_log(tmp_path: Path) -> None:
    """HostLogService must own a SignedAppendOnlyLog bound to the identity."""
    identity = _make_identity(tmp_path, "id.json")
    host_log_path = tmp_path / "host.log"

    service = HostLogService(
        host_log_path=str(host_log_path),
        identity=identity,
    )

    assert isinstance(service.log, SignedAppendOnlyLog), (
        f"expected service.log to be a SignedAppendOnlyLog, got {type(service.log).__name__}"
    )

    service.seed_evidence()

    entries = service.log.read_entries()
    assert len(entries) >= 1, f"expected at least 1 seeded entry, got {len(entries)}"

    entry = entries[0]
    assert isinstance(entry.get("signature"), str) and entry["signature"], (
        "seeded entry is missing a non-empty signature field"
    )
    assert isinstance(entry.get("reporter_pubkey"), str) and entry["reporter_pubkey"], (
        "seeded entry is missing a non-empty reporter_pubkey field"
    )

    ok, errors = service.verify()
    assert (ok, errors) == (True, []), (
        f"service.verify() failed: ok={ok}, errors={errors}"
    )


def test_host_log_service_proxy_uses_identity_hash(tmp_path: Path) -> None:
    """The proxy on a HostLogService must report under the identity_hash so
    that signed-log verify_integrity passes (signature binds reporter_id to
    reporter_pubkey).
    """
    identity = _make_identity(tmp_path, "id.json")
    host_log_path = tmp_path / "host.log"

    service = HostLogService(
        host_log_path=str(host_log_path),
        agent_id="compromised-agent",
        identity=identity,
    )

    service.proxy.log_action("tool_execution_success", {"foo": "bar"})

    entries = service.log.read_entries()
    assert entries, "proxy.log_action produced no entries"

    entry = entries[-1]
    assert entry.get("reporter_id") == identity.identity_hash, (
        f"expected reporter_id={identity.identity_hash!r}, "
        f"got {entry.get('reporter_id')!r}"
    )

    ok, errors = service.verify()
    assert (ok, errors) == (True, []), (
        f"service.verify() failed: ok={ok}, errors={errors}"
    )


def test_log_tamper_suite_spoof_attack_detected_by_signed_log(tmp_path: Path) -> None:
    """The spoof_append attack against the host log must be detected as a
    signature mismatch by the signed log (integrity_ok is False), not merely
    by a hash diff.
    """
    identity = _make_identity(tmp_path, "id.json")
    host_log_path = tmp_path / "host" / "host.log"
    workspace_path = tmp_path / "workspace"

    suite = LogTamperSuite(
        host_log_path=str(host_log_path),
        workspace_path=str(workspace_path),
        identity=identity,
    )

    result = suite.run(expose_host_log_path=True)

    spoof_attempts = [a for a in result.attempts if a.attack_name == "spoof_append"]
    assert spoof_attempts, (
        f"expected a spoof_append attempt, got attacks="
        f"{[a.attack_name for a in result.attempts]}"
    )
    attempt = spoof_attempts[0]

    assert attempt.succeeded is True, (
        f"spoof_append should write to file (succeeded=True), got {attempt.succeeded!r}"
    )
    assert attempt.integrity_ok is False, (
        "spoof_append must be caught by signature verification "
        f"(integrity_ok=False), got integrity_ok={attempt.integrity_ok!r}"
    )


def test_run_log_integrity_experiment_signature_compat(tmp_path: Path) -> None:
    """The module-level helper signature stays backward compatible: no
    identity parameter required from callers.
    """
    host_dir = tmp_path / "host"
    workspace_dir = tmp_path / "workspace"

    out = run_log_integrity_experiment(
        host_dir=str(host_dir),
        workspace_dir=str(workspace_dir),
    )

    assert isinstance(out, tuple), f"expected a tuple result, got {type(out).__name__}"
    assert len(out) == 2, f"expected 2-tuple (no_isolation, proxy_only), got {len(out)}"

    no_isolation, proxy_only = out

    assert len(no_isolation.attempts) == 6, (
        f"expected 6 attacks in no_isolation, got {len(no_isolation.attempts)}: "
        f"{[a.attack_name for a in no_isolation.attempts]}"
    )
    assert len(proxy_only.attempts) == 6, (
        f"expected 6 attacks in proxy_only, got {len(proxy_only.attempts)}: "
        f"{[a.attack_name for a in proxy_only.attempts]}"
    )
    assert any(a.attempted for a in no_isolation.attempts), (
        "expected at least one attempted attack in no_isolation"
    )


def test_log_tamper_suite_delete_attack_yields_integrity_false(tmp_path: Path) -> None:
    """Defensive: the delete attack must surface as integrity_ok=False.

    Locks in the order-of-operations in ``_run_single_attack``: the
    ``host_log_deleted`` check must happen *before* a fresh
    ``SignedAppendOnlyLog`` is constructed against the missing file, otherwise
    the constructor would silently re-create a header-only file and the
    verifier would return ``(True, [])``, masking the deletion. This test
    documents the current contract so a future refactor can't regress it.
    """
    identity = _make_identity(tmp_path, "id.json")
    host_log_path = tmp_path / "host" / "host.log"
    workspace_path = tmp_path / "workspace"

    suite = LogTamperSuite(
        host_log_path=str(host_log_path),
        workspace_path=str(workspace_path),
        identity=identity,
    )

    result = suite.run(expose_host_log_path=True)

    delete_attempts = [a for a in result.attempts if a.attack_name == "delete"]
    assert delete_attempts, (
        f"expected a delete attempt, got attacks="
        f"{[a.attack_name for a in result.attempts]}"
    )
    attempt = delete_attempts[0]

    assert attempt.host_log_deleted is True, (
        f"delete attack must mark host_log_deleted=True, got "
        f"{attempt.host_log_deleted!r}"
    )
    assert attempt.integrity_ok is False, (
        "delete attack must surface as integrity_ok=False (not silently masked "
        f"by a re-constructed header-only log), got integrity_ok={attempt.integrity_ok!r}"
    )
    assert attempt.succeeded is True, (
        f"delete attack should report succeeded=True, got {attempt.succeeded!r}"
    )


def test_log_tamper_suite_overwrite_attack_yields_integrity_false(tmp_path: Path) -> None:
    """Defensive: the overwrite attack must surface as integrity_ok=False.

    Overwriting the host log with non-signed bytes must trip signature
    verification on the rebuilt ``SignedAppendOnlyLog``. This locks in the
    semantic that detection comes from signature verification (not merely a
    hash diff), parallel to the existing spoof_append test.
    """
    identity = _make_identity(tmp_path, "id.json")
    host_log_path = tmp_path / "host" / "host.log"
    workspace_path = tmp_path / "workspace"

    suite = LogTamperSuite(
        host_log_path=str(host_log_path),
        workspace_path=str(workspace_path),
        identity=identity,
    )

    result = suite.run(expose_host_log_path=True)

    overwrite_attempts = [a for a in result.attempts if a.attack_name == "overwrite"]
    assert overwrite_attempts, (
        f"expected an overwrite attempt, got attacks="
        f"{[a.attack_name for a in result.attempts]}"
    )
    attempt = overwrite_attempts[0]

    assert attempt.host_log_changed is True, (
        f"overwrite attack must mark host_log_changed=True, got "
        f"{attempt.host_log_changed!r}"
    )
    assert attempt.integrity_ok is False, (
        "overwrite attack must surface as integrity_ok=False via signature "
        f"verification, got integrity_ok={attempt.integrity_ok!r}"
    )
    assert attempt.succeeded is True, (
        f"overwrite attack should report succeeded=True, got {attempt.succeeded!r}"
    )
