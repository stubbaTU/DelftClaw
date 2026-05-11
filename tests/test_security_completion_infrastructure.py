from __future__ import annotations

from pathlib import Path

from security.integration.gateway import GatewayState
from security.integration.ports import NoopEvidencePublisher, SecurityIdentity, StaticIdentityProvider
from security.integration.security_readiness import run_security_readiness


def test_security_readiness_without_identity_or_communication(tmp_path: Path) -> None:
    report = run_security_readiness(artifact_dir=tmp_path / "sandbox")

    assert report["ok"] is True
    assert (tmp_path / "sandbox" / "Dockerfile.gvisor").exists()
    assert (tmp_path / "sandbox" / "iptables_sandbox.sh").exists()


def test_security_ports_allow_static_identity_and_noop_publisher() -> None:
    provider = StaticIdentityProvider(SecurityIdentity(agent_id="agent-a", network="TESTNET"))
    publisher = NoopEvidencePublisher()

    assert provider.current_identity().agent_id == "agent-a"
    publisher.publish({"action": "atomic_microtask_claimed"})
    assert publisher.published == [{"action": "atomic_microtask_claimed"}]


def test_gateway_claims_and_verifies_atomic_microtasks(tmp_path: Path) -> None:
    state = GatewayState(
        local_agent_id="agent-a",
        log_path=str(tmp_path / "gateway.jsonl"),
        run_id="security-completion",
    )

    registered = state.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "register_seedbox",
            "tool_kwargs": {
                "seedbox_id": "seedbox-a",
                "donation_address": "donate-a",
                "advertised_capacity_gb": 100,
            },
        }
    )
    assert registered["ok"] is True

    claimed = state.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "submit_atomic_microtask",
            "tool_kwargs": {
                "task_id": "task-a",
                "seedbox_id": "seedbox-a",
                "file_hash": "file-sha",
                "result_hash": "result-sha",
            },
        }
    )
    assert claimed["ok"] is True

    verified = state.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "verify_atomic_microtask",
            "tool_kwargs": {
                "task_id": "task-a",
                "expected_result_hash": "result-sha",
            },
        }
    )
    assert verified["ok"] is True

    entries = state.log.read_entries()
    assert [entry["action"] for entry in entries].count("atomic_microtask_claimed") == 1
    assert [entry["action"] for entry in entries].count("atomic_microtask_verified") == 1
