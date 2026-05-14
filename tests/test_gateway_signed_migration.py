"""Red-step TDD tests for Phase E gateway migration.

These tests assert that ``GatewayState`` builds a ``SignedAppendOnlyLog``
(not the unsigned ``AppendOnlyLog``), produces verifiable signed entries
from tool calls, exposes run_id / experiment_condition / integrity_ok
through ``metrics()`` even though ``run_metadata`` is dropped from the
log construction, and supports state replay across instances sharing the
same log file. They are expected to FAIL until the Green step of Phase E
is implemented.

Per Phase B/D precedent, ``GatewayState`` accepts an optional
``identity`` parameter and synthesizes one when None. No caller in the
existing test suite passes ``identity``.

The tests do NOT pin a specific value for ``reporter_id`` — they only
require that ``verify_integrity()`` passes, which under the signed log's
network rule binds ``reporter_id`` to ``reporter_pubkey``. The Green
step is free to either rewrite the 4 ``reporter_id=self.local_agent_id``
call sites to use ``self._identity.identity_hash`` or override
``self.local_agent_id`` to be the identity hash when synthesizing.
"""

from __future__ import annotations

from pathlib import Path

from redteam.primitives.signed_log import SignedAppendOnlyLog
from security.integration.gateway import GatewayState


def test_gateway_state_builds_signed_log(tmp_path: Path) -> None:
    """GatewayState.log must be a SignedAppendOnlyLog after migration."""
    state = GatewayState(
        local_agent_id="agent-a",
        log_path=str(tmp_path / "gateway.jsonl"),
        run_id="test-run",
    )

    assert isinstance(state.log, SignedAppendOnlyLog), (
        f"expected state.log to be a SignedAppendOnlyLog, "
        f"got {type(state.log).__name__}"
    )


def test_gateway_tool_call_produces_signed_verifiable_entries(tmp_path: Path) -> None:
    """A register_seedbox tool call must write signed entries that verify."""
    state = GatewayState(
        local_agent_id="agent-a",
        log_path=str(tmp_path / "gateway.jsonl"),
        run_id="test-run",
    )

    state.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "register_seedbox",
            "tool_kwargs": {
                "seedbox_id": "sb-1",
                "donation_address": "donate-1",
                "advertised_capacity_gb": 100,
            },
        }
    )

    entries = state.log.read_entries()
    assert len(entries) >= 1, (
        f"expected at least one log entry, got {len(entries)}"
    )

    for i, entry in enumerate(entries):
        assert isinstance(entry.get("signature"), str) and entry["signature"], (
            f"entry {i} (action={entry.get('action')!r}) is missing a "
            "non-empty signature field"
        )
        assert (
            isinstance(entry.get("reporter_pubkey"), str)
            and entry["reporter_pubkey"]
        ), (
            f"entry {i} (action={entry.get('action')!r}) is missing a "
            "non-empty reporter_pubkey field"
        )
        assert entry.get("version") == 2, (
            f"entry {i}: expected version 2, got {entry.get('version')!r}"
        )

    ok, errors = state.log.verify_integrity()
    assert (ok, errors) == (True, []), (
        f"verify_integrity failed: ok={ok}, errors={errors}"
    )


def test_gateway_metrics_endpoint_returns_run_id_and_integrity_ok(
    tmp_path: Path,
) -> None:
    """metrics() must still surface run_id / experiment_condition and report
    integrity_ok=True after the migration drops run_metadata from the log.
    """
    state = GatewayState(
        local_agent_id="agent-a",
        log_path=str(tmp_path / "gateway.jsonl"),
        run_id="experiment-001",
        experiment_condition="defended",
    )

    state.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "register_seedbox",
            "tool_kwargs": {
                "seedbox_id": "sb-1",
                "donation_address": "donate-1",
                "advertised_capacity_gb": 100,
            },
        }
    )

    metrics = state.metrics()

    assert metrics["run_id"] == "experiment-001", (
        f"expected metrics['run_id']='experiment-001', got {metrics['run_id']!r}"
    )
    assert metrics["experiment_condition"] == "defended", (
        f"expected metrics['experiment_condition']='defended', "
        f"got {metrics['experiment_condition']!r}"
    )
    assert metrics["integrity_ok"] is True, (
        f"expected metrics['integrity_ok']=True, got {metrics['integrity_ok']!r} "
        f"(errors={metrics.get('integrity_errors')!r})"
    )
    assert metrics["integrity_errors"] == [], (
        f"expected metrics['integrity_errors']=[], got {metrics['integrity_errors']!r}"
    )


def test_gateway_log_entries_do_not_carry_run_metadata(tmp_path: Path) -> None:
    """After migration, log entries no longer carry run_id /
    experiment_condition (those flow out via metrics() instead).
    """
    state = GatewayState(
        local_agent_id="agent-a",
        log_path=str(tmp_path / "gateway.jsonl"),
        run_id="x",
        experiment_condition="y",
    )

    state.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "register_seedbox",
            "tool_kwargs": {
                "seedbox_id": "sb-1",
                "donation_address": "donate-1",
                "advertised_capacity_gb": 100,
            },
        }
    )

    entries = state.log.read_entries()
    assert entries, "tool call produced no log entries"

    for i, entry in enumerate(entries):
        assert entry.get("run_id") is None, (
            f"entry {i} (action={entry.get('action')!r}) unexpectedly carries "
            f"run_id={entry.get('run_id')!r} — log should not contain run_metadata"
        )
        assert entry.get("experiment_condition") is None, (
            f"entry {i} (action={entry.get('action')!r}) unexpectedly carries "
            f"experiment_condition={entry.get('experiment_condition')!r} — "
            "log should not contain run_metadata"
        )


def test_gateway_state_replay_across_instances_with_signed_log(
    tmp_path: Path,
) -> None:
    """A second GatewayState pointed at the same signed log file must
    replay state (registered seedbox) without reload errors and with
    integrity_ok=True.
    """
    log_path = str(tmp_path / "gateway.jsonl")

    state1 = GatewayState(
        local_agent_id="agent-a",
        log_path=log_path,
        run_id="replay-run",
    )

    state1.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "register_seedbox",
            "tool_kwargs": {
                "seedbox_id": "sb-1",
                "donation_address": "donate-1",
                "advertised_capacity_gb": 100,
            },
        }
    )

    # Drop first instance.
    del state1

    state2 = GatewayState(
        local_agent_id="agent-a",
        log_path=log_path,
        run_id="replay-run",
    )

    assert state2.state_reload_errors == [], (
        f"second instance had reload errors: {state2.state_reload_errors!r}"
    )
    assert "sb-1" in state2.registry.seedboxes, (
        f"second instance did not replay registered seedbox 'sb-1'; "
        f"seen seedbox_ids={list(state2.registry.seedboxes.keys())!r}"
    )

    metrics = state2.metrics()
    assert metrics["integrity_ok"] is True, (
        f"second instance metrics['integrity_ok']={metrics['integrity_ok']!r} "
        f"(errors={metrics.get('integrity_errors')!r})"
    )


def test_two_gateways_with_different_agent_ids_use_distinct_identity_files(tmp_path: Path) -> None:
    """Two GatewayStates with different local_agent_id in the same log_dir
    must NOT share a synthetic identity file."""
    log_dir = tmp_path / "logs"
    state_a = GatewayState(
        local_agent_id="agent-a",
        log_path=str(log_dir / "a.jsonl"),
    )
    state_b = GatewayState(
        local_agent_id="agent-b",
        log_path=str(log_dir / "b.jsonl"),
    )
    # Each should have its own identity key file
    assert state_a._identity.identity_hash != state_b._identity.identity_hash
    # Both identity files must exist on disk
    assert (log_dir / ".gateway_identity_agent-a.json").exists()
    assert (log_dir / ".gateway_identity_agent-b.json").exists()
