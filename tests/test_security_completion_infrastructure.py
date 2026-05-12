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


def test_gateway_indexes_and_searches_seedbox_files(tmp_path: Path) -> None:
    state = GatewayState(
        local_agent_id="agent-a",
        log_path=str(tmp_path / "gateway.jsonl"),
        run_id="content-index",
    )

    state.handle_tool_call(
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
    indexed = state.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "index_seedbox_file",
            "tool_kwargs": {
                "file_id": "cc-audio-2023-001",
                "seedbox_id": "seedbox-a",
                "name": "Creative Commons Audio Archive 2023 - Track 1",
                "content_url": "https://example.invalid/audio/track-1.mp3",
                "media_type": "audio/mpeg",
                "tags": ["Creative Commons", "audio"],
            },
        }
    )
    assert indexed["ok"] is True

    search = state.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "search_seedbox_files",
            "tool_kwargs": {"query": "Creative Commons"},
        }
    )
    assert search["ok"] is True
    assert search["result"]["output"]["count"] == 1

    picked = state.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "pick_random_seedbox_file",
            "tool_kwargs": {"query": "Creative Commons Audio Archive 2023"},
        }
    )
    assert picked["ok"] is True
    assert picked["result"]["output"]["playback_intent"]["url"] == "https://example.invalid/audio/track-1.mp3"


def test_gateway_reloads_seedboxes_and_indexed_files_from_append_only_log(tmp_path: Path) -> None:
    log_path = tmp_path / "gateway.jsonl"
    first = GatewayState(
        local_agent_id="agent-a",
        log_path=str(log_path),
        run_id="content-index-reload",
    )

    first.handle_tool_call(
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
    first.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "index_seedbox_file",
            "tool_kwargs": {
                "file_id": "cc-audio-2023-001",
                "seedbox_id": "seedbox-a",
                "name": "Creative Commons Audio Archive 2023 - Track 1",
                "content_url": "https://example.invalid/audio/track-1.mp3",
                "media_type": "audio/mpeg",
                "tags": ["Creative Commons", "audio"],
            },
        }
    )

    restarted = GatewayState(
        local_agent_id="agent-a",
        log_path=str(log_path),
        run_id="content-index-reload",
    )
    assert restarted.state_reload_errors == []

    search = restarted.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "search_seedbox_files",
            "tool_kwargs": {"query": "audio"},
        }
    )
    assert search["ok"] is True
    assert search["result"]["output"]["count"] == 1
    assert search["result"]["output"]["files"][0]["seedbox_id"] == "seedbox-a"


def test_gateway_reloads_seedbox_donations_for_audits(tmp_path: Path) -> None:
    log_path = tmp_path / "gateway.jsonl"
    first = GatewayState(
        local_agent_id="agent-a",
        log_path=str(log_path),
        run_id="seedbox-audit-reload",
    )

    first.handle_tool_call(
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
    first.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "broadcast_seedbox_donation",
            "tool_kwargs": {
                "seedbox_id": "seedbox-a",
                "amount_sats": 1000,
                "txid": "tx-a",
            },
        }
    )

    restarted = GatewayState(
        local_agent_id="agent-a",
        log_path=str(log_path),
        run_id="seedbox-audit-reload",
    )

    audit = restarted.audit_seedboxes()
    assert audit["finding_count"] == 1
    assert audit["findings"][0]["seedbox_id"] == "seedbox-a"

    restarted_again = GatewayState(
        local_agent_id="agent-a",
        log_path=str(log_path),
        run_id="seedbox-audit-reload",
    )
    duplicate_audit = restarted_again.audit_seedboxes()
    assert duplicate_audit["finding_count"] == 0
