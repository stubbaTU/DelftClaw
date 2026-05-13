from __future__ import annotations

from pathlib import Path

from identity.agent_identity import AgentIdentity
from security.integration.gateway import GatewayState
from security.integration.ports import AgentIdentityProvider, NoopEvidencePublisher, SecurityIdentity, StaticIdentityProvider
from security.integration.security_readiness import run_security_readiness
from security.subq2_accountability.bitcoin_anchor import BitcoinAnchorVerifier


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


def test_security_identity_provider_adapts_shared_agent_identity() -> None:
    identity = AgentIdentity(network="TESTNET", agent_index=0)
    provider = AgentIdentityProvider(identity)

    snapshot = provider.current_identity()

    assert snapshot.agent_id == identity.identity_hash
    assert snapshot.identity_hash == identity.identity_hash
    assert snapshot.network == "TESTNET"
    assert snapshot.ipv8_public_key == identity.ipv8.public_key_bytes.hex()
    assert snapshot.wallet_public_key == identity.wallet.xpub


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


def test_bitcoin_anchor_verifier_accepts_chain_shaped_and_mock_txids() -> None:
    verifier = BitcoinAnchorVerifier(network="mock")

    chain_anchor = verifier.build_anchor(
        txid="a" * 64,
        donation_address="tb1q-demo",
        amount_sats=1000,
        seedbox_id="seedbox-a",
    )
    mock_anchor = verifier.build_anchor(
        txid="mock-tx-agent-a-1",
        donation_address="tb1q-demo",
        amount_sats=1000,
        seedbox_id="seedbox-a",
    )
    invalid_anchor = verifier.build_anchor(
        txid="not a transaction id",
        donation_address="tb1q-demo",
        amount_sats=1000,
        seedbox_id="seedbox-a",
    )

    assert chain_anchor.verified is True
    assert mock_anchor.verified is True
    assert invalid_anchor.verified is False
    assert chain_anchor.anchor_id != mock_anchor.anchor_id


def test_gateway_logs_and_reloads_bitcoin_anchor_for_donation(tmp_path: Path) -> None:
    log_path = tmp_path / "gateway.jsonl"
    state = GatewayState(
        local_agent_id="agent-a",
        log_path=str(log_path),
        run_id="bitcoin-anchor",
    )
    state.handle_tool_call(
        {
            "agent_id": "agent-a",
            "tool_name": "register_seedbox",
            "tool_kwargs": {
                "seedbox_id": "seedbox-a",
                "donation_address": "tb1q-demo",
                "advertised_capacity_gb": 100,
            },
        }
    )

    donation = state.handle_tool_call(
        {
            "agent_id": "agent-b",
            "tool_name": "broadcast_seedbox_donation",
            "tool_kwargs": {
                "seedbox_id": "seedbox-a",
                "amount_sats": 1000,
                "txid": "a" * 64,
                "confirmations": 3,
                "output_index": 0,
            },
        }
    )

    anchor = donation["result"]["output"]["donation"]["bitcoin_anchor"]
    assert anchor["verified"] is True
    assert anchor["network"] == "mock"
    assert anchor["confirmations"] == 3
    assert anchor["output_index"] == 0

    restarted = GatewayState(
        local_agent_id="agent-a",
        log_path=str(log_path),
        run_id="bitcoin-anchor",
    )
    assert restarted.ledger.donations[0].bitcoin_anchor is not None
    assert restarted.ledger.donations[0].bitcoin_anchor.verified is True
