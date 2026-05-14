"""Phase 8 tests: ``seedbox_provisioned`` tool — closing a purchase intent.

Coverage:
  - rejected before manifest loaded / before admission
  - rejected when purchase_intent_hash is unknown to community state
  - rejected when same intent is closed twice
  - accept path bumps seedbox_count from 1 to 2

Set-up mirrors ``tests/test_community_tools.py``: a started
``OpenClawAgent`` with a manifest + community log, no IPv8 wire
plumbing. We hand-seed 3 peer donor logs to push member_count past the
threshold so a purchase intent can land.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio

from agent import AgentConfig, OpenClawAgent, build_tools
from communication.bittorrent import StubBitTorrentService
from identity.agent_identity import AgentIdentity
from identity.openclaw_identity import OpenClawIdentity
from identity.seed import MnemonicSeedSource
from protocol import StubLLMClient
from redteam.primitives.signed_log import SignedAppendOnlyLog


MANIFEST_TEMPLATE = """\
# Identity

- name: provisioning_test
- version: 1.0.0
- description: Phase 8 seedbox_provisioned tool test fixture.

# Admission

- gatekeeper_address: {gatekeeper_address}
- min_sats: 10000
- min_confirmations: 0
- bootstrap_cap_sats: 100000
- max_agents_per_seedbox: 3
- seedbox_cost_sats: 50000

# Genesis Peers

| host | port | pubkey_hex |
|------|------|------------|
| 127.0.0.1 | 8190 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |

# Default Overlays

- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a
"""


def _seed_peer_donation(peer_log_dir, mnemonic: str, nid_hex: str, amount: int) -> str:
    """Write a signed donation_intent into the agent's peer_log cache as if pulled."""
    seed = MnemonicSeedSource(mnemonic).load()
    identity = AgentIdentity.from_seed(seed, network="TESTNET")
    oc = OpenClawIdentity.from_agent_identity(identity)
    log_path = peer_log_dir / f"{oc.identity_hash}.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    peer_log = SignedAppendOnlyLog(oc, str(log_path))
    peer_log.append_event(
        reporter_id=oc.identity_hash,
        subject_id=oc.identity_hash,
        action="donation_intent",
        details={"network_id_hex": nid_hex, "amount_sats": amount},
    )
    return oc.identity_hash


@pytest_asyncio.fixture
async def admitted_agent_with_threshold(tmp_path):
    """Alice + three pre-seeded peer donors → 4 members → threshold tripped."""
    save_dir = tmp_path / "alice"
    save_dir.mkdir()
    peer_log_dir = save_dir / "peer_logs"

    seed = MnemonicSeedSource(
        "army van defense carry jealous true garbage claim echo media make crunch"
    ).load()
    agent = OpenClawAgent(
        identity=AgentIdentity.from_seed(seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=save_dir,
            initial_balance_sats=200_000,
            community_log_path=save_dir / "community.log",
            peer_log_dir=peer_log_dir,
        ),
        bt_service=StubBitTorrentService(save_dir=save_dir),
    )
    await agent.start()

    manifest_md = MANIFEST_TEMPLATE.format(gatekeeper_address=agent.wallet.address())
    agent.load_manifest(manifest_md)
    nid_hex = agent.network_manifest.network_id.hex()

    # Seed three peer donations FIRST so the running-average cap is
    # established before alice donates (otherwise alice as donor #1
    # would trip the bootstrap cap path, which uses a different rule).
    for mnemonic in [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ]:
        _seed_peer_donation(peer_log_dir, mnemonic, nid_hex, amount=60_000)

    # Alice donates last → 4 members, threshold = 3 * seedbox_count(1) = 3,
    # member_count > 3 → tripped.
    tools = build_tools(agent)
    await tools.dispatch("community_donate_and_join", {"amount_sats": 60_000})

    yield agent, tools, nid_hex
    await agent.stop()


# ---------------------------------------------------------------------------
# Tool surface presence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seedbox_provisioned_tool_is_registered(admitted_agent_with_threshold):
    agent, tools, _nid = admitted_agent_with_threshold
    assert "seedbox_provisioned" in tools.names()


# ---------------------------------------------------------------------------
# Rejection cases (no manifest / not admitted / unknown intent / double-close)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seedbox_provisioned_rejected_when_no_manifest(tmp_path):
    save_dir = tmp_path / "x"
    save_dir.mkdir()
    agent = OpenClawAgent(
        identity=AgentIdentity.from_seed(
            MnemonicSeedSource(
                "army van defense carry jealous true garbage claim echo media make crunch"
            ).load(),
            network="TESTNET",
        ),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=save_dir,
            community_log_path=save_dir / "community.log",
            peer_log_dir=save_dir / "peer_logs",
        ),
        bt_service=StubBitTorrentService(save_dir=save_dir),
    )
    await agent.start()
    try:
        tools = build_tools(agent)
        result = await tools.dispatch(
            "seedbox_provisioned",
            {
                "purchase_intent_hash": "deadbeef" * 8,
                "seedbox_url": "mock-seedbox-2.delftclaw.test:18769",
                "seedbox_pubkey_hex": "ff" * 32,
            },
        )
        assert result == {"error": "no_manifest_loaded"}
    finally:
        await agent.stop()


@pytest.mark.asyncio
async def test_seedbox_provisioned_rejected_when_not_admitted(tmp_path):
    """A node that loaded the manifest but never donated can't close intents."""
    save_dir = tmp_path / "x"
    save_dir.mkdir()
    agent = OpenClawAgent(
        identity=AgentIdentity.from_seed(
            MnemonicSeedSource(
                "army van defense carry jealous true garbage claim echo media make crunch"
            ).load(),
            network="TESTNET",
        ),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=save_dir,
            community_log_path=save_dir / "community.log",
            peer_log_dir=save_dir / "peer_logs",
        ),
        bt_service=StubBitTorrentService(save_dir=save_dir),
    )
    await agent.start()
    try:
        manifest_md = MANIFEST_TEMPLATE.format(gatekeeper_address=agent.wallet.address())
        agent.load_manifest(manifest_md)
        tools = build_tools(agent)
        result = await tools.dispatch(
            "seedbox_provisioned",
            {
                "purchase_intent_hash": "deadbeef" * 8,
                "seedbox_url": "mock-seedbox-2.delftclaw.test:18769",
                "seedbox_pubkey_hex": "ff" * 32,
            },
        )
        assert result == {"error": "not_admitted"}
    finally:
        await agent.stop()


@pytest.mark.asyncio
async def test_seedbox_provisioned_rejects_unknown_purchase_intent(
    admitted_agent_with_threshold,
):
    agent, tools, _nid = admitted_agent_with_threshold
    # Threshold is tripped + agent admitted, but the hash points at
    # nothing in state.purchases.
    result = await tools.dispatch(
        "seedbox_provisioned",
        {
            "purchase_intent_hash": "00" * 32,
            "seedbox_url": "mock-seedbox-2.delftclaw.test:18769",
            "seedbox_pubkey_hex": "ff" * 32,
        },
    )
    assert "error" in result
    assert "no_matching_purchase_intent" in result["error"]


@pytest.mark.asyncio
async def test_seedbox_provisioned_accepts_and_bumps_seedbox_count(
    admitted_agent_with_threshold,
):
    """Threshold tripped → propose → state.pending_purchases==1 → close → count=2."""
    agent, tools, _nid = admitted_agent_with_threshold

    propose = await tools.dispatch("seedbox_purchase_propose", {})
    assert "entry_hash" in propose, f"propose failed: {propose}"

    state_before = await tools.dispatch("community_treasury_balance", {})
    assert state_before["pending_purchases"] == 1
    assert state_before["seedbox_count"] == 1

    provisioned = await tools.dispatch(
        "seedbox_provisioned",
        {
            "purchase_intent_hash": propose["entry_hash"],
            "seedbox_url": "mock-seedbox-2.delftclaw.test:18769",
            "seedbox_pubkey_hex": "bb" * 32,
        },
    )
    assert "entry_hash" in provisioned, f"provision failed: {provisioned}"
    assert provisioned["purchase_intent_hash"] == propose["entry_hash"]

    state_after = await tools.dispatch("community_treasury_balance", {})
    assert state_after["seedbox_count"] == 2
    assert state_after["pending_purchases"] == 0


@pytest.mark.asyncio
async def test_seedbox_provisioned_rejects_double_close(admitted_agent_with_threshold):
    """A second provisioned event for the same intent is rejected."""
    agent, tools, _nid = admitted_agent_with_threshold

    propose = await tools.dispatch("seedbox_purchase_propose", {})
    intent_hash = propose["entry_hash"]

    first = await tools.dispatch(
        "seedbox_provisioned",
        {
            "purchase_intent_hash": intent_hash,
            "seedbox_url": "sb-A:1",
            "seedbox_pubkey_hex": "aa" * 32,
        },
    )
    assert "entry_hash" in first

    second = await tools.dispatch(
        "seedbox_provisioned",
        {
            "purchase_intent_hash": intent_hash,
            "seedbox_url": "sb-B:1",
            "seedbox_pubkey_hex": "cc" * 32,
        },
    )
    assert second == {"error": "purchase_intent_already_closed"}


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seedbox_provisioned_rejects_empty_args(admitted_agent_with_threshold):
    agent, tools, _nid = admitted_agent_with_threshold
    propose = await tools.dispatch("seedbox_purchase_propose", {})
    # Empty seedbox_url should be rejected before the replay check.
    bad = await tools.dispatch(
        "seedbox_provisioned",
        {
            "purchase_intent_hash": propose["entry_hash"],
            "seedbox_url": "",
            "seedbox_pubkey_hex": "aa" * 32,
        },
    )
    assert "error" in bad
    assert "seedbox_url" in bad["error"]
