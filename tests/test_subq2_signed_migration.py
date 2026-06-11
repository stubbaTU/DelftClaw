"""Red-step TDD tests for Phase B subq2 accountability migration.

These tests assert that ``IsolationProxy``, ``AccountabilityMonitor``, and
``run_reputation_trap_experiment`` write signed log entries — i.e. that
they have been migrated off the unsigned ``AppendOnlyLog`` onto
``SignedAppendOnlyLog``. They are expected to FAIL until the Green step
of Phase B is implemented.

Each test uses ``tmp_path`` for both the identity key file and the log
file to avoid polluting the repo root.
"""

from __future__ import annotations

from pathlib import Path

from identity.openclaw_identity import OpenClawIdentity
from redteam.primitives.signed_log import SignedAppendOnlyLog
from security.accountability_layer.infrastructure.accountability import (
    AccountabilityMonitor,
    run_reputation_trap_experiment,
)
from security.accountability_layer.infrastructure.proxy import IsolationProxy
from security.accountability_layer.infrastructure.reputation import ReputationEngine
from security.accountability_layer.infrastructure.signed_accountability_log import SQ2SignedAccountabilityLog


def _make_identity(tmp_path: Path, name: str = "key.json") -> OpenClawIdentity:
    return OpenClawIdentity(network="MAINNET", key_path=str(tmp_path / name))


def test_isolation_proxy_writes_signed_entries(tmp_path: Path) -> None:
    """IsolationProxy must produce signed entries that pass verify_integrity."""
    identity = _make_identity(tmp_path, "proxy_key.json")
    log_path = tmp_path / "proxy.jsonl"
    log = SignedAppendOnlyLog(identity, log_path=str(log_path))

    proxy = IsolationProxy(agent_id=identity.identity_hash, logger=log)
    proxy.log_action("tool_execution_success", {"tool": "noop"})

    entries = log.read_entries()
    assert len(entries) == 1, f"expected exactly 1 entry, got {len(entries)}"

    entry = entries[0]
    assert isinstance(entry.get("signature"), str) and entry["signature"], (
        "entry is missing a non-empty signature field"
    )
    assert isinstance(entry.get("reporter_pubkey"), str) and entry["reporter_pubkey"], (
        "entry is missing a non-empty reporter_pubkey field"
    )
    assert entry.get("version") == 2, f"expected version 2, got {entry.get('version')!r}"
    assert entry.get("kind") == "self", f"expected kind='self', got {entry.get('kind')!r}"
    assert entry.get("action") == "tool_execution_success", (
        f"expected action='tool_execution_success', got {entry.get('action')!r}"
    )

    ok, errors = log.verify_integrity()
    assert (ok, errors) == (True, []), (
        f"verify_integrity failed: ok={ok}, errors={errors}"
    )


def test_accountability_monitor_with_signed_log_records_signed_entry(
    tmp_path: Path,
) -> None:
    """AccountabilityMonitor must accept a SignedAppendOnlyLog and emit signed entries."""
    identity = _make_identity(tmp_path, "monitor_key.json")
    log_path = tmp_path / "monitor.jsonl"
    log = SignedAppendOnlyLog(identity, log_path=str(log_path))
    reputation = ReputationEngine(log_path=log.log_path, ban_threshold=10)

    monitor = AccountabilityMonitor(
        log=log,
        reputation=reputation,
        reporter_id=identity.identity_hash,
    )
    monitor.next_step()
    monitor.record_unauthorized_execution(
        subject_id=identity.identity_hash,
        tool_name="exfiltrate_private_key",
        details={"step": 1},
    )

    entries = log.read_entries()
    assert len(entries) >= 1, "expected at least one entry"

    unauthorized = [
        e for e in entries if e.get("action") == "unauthorized_tool_execution"
    ]
    assert unauthorized, (
        "expected at least one entry with action='unauthorized_tool_execution', "
        f"got actions={[e.get('action') for e in entries]}"
    )
    entry = unauthorized[0]
    assert isinstance(entry.get("signature"), str) and entry["signature"], (
        "unauthorized_tool_execution entry missing a non-empty signature"
    )
    assert isinstance(entry.get("reporter_pubkey"), str) and entry["reporter_pubkey"], (
        "unauthorized_tool_execution entry missing a non-empty reporter_pubkey"
    )

    ok, errors = log.verify_integrity()
    assert (ok, errors) == (True, []), (
        f"verify_integrity failed: ok={ok}, errors={errors}"
    )


def test_run_reputation_trap_experiment_produces_signed_log(tmp_path: Path) -> None:
    """The standalone experiment helper must produce a signed log."""
    log_path = tmp_path / "experiment.jsonl"

    run_reputation_trap_experiment(
        accountability_enabled=True,
        total_malicious_actions=3,
        threshold=20,
        scan_interval=1,
        log_path=str(log_path),
    )

    assert log_path.exists(), "experiment did not create a log file"

    # Re-open the produced file through a fresh signed log over the same
    # path. We don't need to know which identity the experiment used —
    # read_entries doesn't care about the identity, only verify_integrity
    # does, and we only inspect entry shape here.
    inspector_identity = OpenClawIdentity(
        network="MAINNET", key_path=str(tmp_path / "inspector_key.json")
    )
    inspector = SignedAppendOnlyLog(inspector_identity, log_path=str(log_path))
    entries = inspector.read_entries()
    assert entries, "experiment produced no log entries"

    for i, entry in enumerate(entries):
        assert isinstance(entry.get("signature"), str) and entry["signature"], (
            f"entry {i} (action={entry.get('action')!r}) missing non-empty signature"
        )
        assert (
            isinstance(entry.get("reporter_pubkey"), str)
            and entry["reporter_pubkey"]
        ), (
            f"entry {i} (action={entry.get('action')!r}) "
            "missing non-empty reporter_pubkey"
        )

    ok, errs = inspector.verify_integrity()
    assert ok, f"chain failed integrity: {errs}"


def test_sq2_signed_accountability_log_adapter_exports_and_detects_tampering(tmp_path: Path) -> None:
    identity = _make_identity(tmp_path, "sq2_adapter_key.json")
    log = SQ2SignedAccountabilityLog(identity, tmp_path / "sq2_adapter.jsonl")

    log.append({
        "event_index": 1,
        "round": 1,
        "actor_id": "M0",
        "event_type": "donation_broadcast",
        "payload": {"from": "M0", "to": "S1"},
    })
    export_path = tmp_path / "exported.jsonl"
    log.export_jsonl(export_path)

    assert export_path.exists()
    assert log.verify_chain() is True

    text = Path(log.log_path).read_text(encoding="utf-8")
    Path(log.log_path).write_text(text.replace("donation_broadcast", "reward_redirect_attempt"), encoding="utf-8")

    assert log.verify_chain() is False
