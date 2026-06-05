from __future__ import annotations

import pytest
import pytest_asyncio

from agent import AgentConfig, OpenClawAgent, build_tools
from communication.bittorrent import StubBitTorrentService
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol import StubLLMClient


@pytest_asyncio.fixture
async def lineage_agent(tmp_path):
    save_dir = tmp_path / "alice"
    identity = AgentIdentity.from_seed(
        MnemonicSeedSource(
            "army van defense carry jealous true garbage claim echo media make crunch"
        ).load(),
        network="TESTNET",
    )
    agent = OpenClawAgent(
        identity=identity,
        llm=StubLLMClient(sources={}),
        config=AgentConfig(port=0, save_dir=save_dir),
        bt_service=StubBitTorrentService(save_dir=save_dir),
    )
    await agent.start()
    yield agent
    await agent.stop()


def _child_identity() -> AgentIdentity:
    return AgentIdentity.from_seed(
        MnemonicSeedSource(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).load(),
        network="TESTNET",
    )


@pytest.mark.asyncio
async def test_lineage_tools_are_registered_and_default_disabled(lineage_agent):
    tools = build_tools(lineage_agent)

    assert {
        "lineage_status",
        "lineage_issue_child_certificate",
        "lineage_verify_proof",
        "lineage_revoke_certificate",
        "lineage_list_revocations",
        "lineage_export_birth_package",
    }.issubset(set(tools.names()))

    status = await tools.dispatch("lineage_status", {})
    assert status["enabled"] is False
    assert status["required"] is False
    assert status["enforced"] is False
    assert status["default_btc_network"] == "mock"
    assert status["certificate_count"] == 0


@pytest.mark.asyncio
async def test_lineage_tool_happy_path_issue_verify_revoke_list_export(lineage_agent):
    child = _child_identity()
    tools = build_tools(lineage_agent)

    issued = await tools.dispatch(
        "lineage_issue_child_certificate",
        {
            "family_id": "family-alpha",
            "child_agent_id": child.identity_hash,
            "child_authority_pubkey": child.app.pubkey.hex(),
            "child_operational_pubkey": child.ipv8.raw_pubkey.hex(),
            "capabilities": ["search", "seed"],
            "constraints": {"max_depth": 1},
        },
    )

    assert "error" not in issued
    certificate = issued["certificate"]
    proof = issued["proof"]
    trusted_roots = issued["trusted_roots"]
    assert certificate["parent_agent_id"] == lineage_agent.identity.identity_hash
    assert certificate["child_agent_id"] == child.identity_hash
    assert proof["anchor_record"]["btc_network"] == "mock"

    valid = await tools.dispatch(
        "lineage_verify_proof",
        {
            "proof": proof,
            "trusted_roots": trusted_roots,
            "requested_capability": "search",
        },
    )
    assert valid["ok"] is True
    assert valid["status"] == "valid"
    assert valid["subject_agent_id"] == child.identity_hash

    exported = await tools.dispatch("lineage_export_birth_package", {})
    assert "error" not in exported
    package = exported["package"]
    assert package["enforced"] is False
    assert package["btc_network"] == "mock"
    assert package["certificate_id"] == certificate["certificate_id"]
    assert package["proof"]["leaf_certificate"]["certificate_id"] == certificate["certificate_id"]

    revoked = await tools.dispatch(
        "lineage_revoke_certificate",
        {
            "certificate_id": certificate["certificate_id"],
            "reason": "test revocation",
        },
    )
    assert revoked["certificate_id"] == certificate["certificate_id"]
    assert revoked["revoked_by_agent_id"] == lineage_agent.identity.identity_hash

    revocations = await tools.dispatch(
        "lineage_list_revocations",
        {"certificate_id": certificate["certificate_id"]},
    )
    assert revocations["count"] == 1
    assert revocations["revocations"][0]["event_id"] == revoked["event_id"]

    revoked_result = await tools.dispatch(
        "lineage_verify_proof",
        {
            "proof": proof,
            "trusted_roots": trusted_roots,
            "requested_capability": "search",
        },
    )
    assert revoked_result["ok"] is False
    assert revoked_result["status"] == "revoked"

    exported_after_revoke = await tools.dispatch("lineage_export_birth_package", {})
    exported_events = exported_after_revoke["package"]["revocation_feed"]
    assert [event["event_id"] for event in exported_events] == [revoked["event_id"]]
