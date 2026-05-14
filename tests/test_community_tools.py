"""Tests for the 5 community-log tools added in Phase 4.

The tools wire ``agent.community_state.replay_community`` into the
LLM-facing surface. Each tool is dispatched through the ``ToolRegistry``
just as the production loop would call it.

Set-up pattern: one started OpenClawAgent with a fresh signed log + an
injected manifest. We do not start IPv8 fully (no peer wiring) — these
tests assert *local* tool behaviour: validation, log writes, replay
state. End-to-end multi-agent gossip is Phase 6's responsibility.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio

from agent import AgentConfig, OpenClawAgent, build_tools
from communication.bittorrent import StubBitTorrentService
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol import StubLLMClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


MANIFEST_TEMPLATE = """\
# Identity

- name: community_tools_test
- version: 1.0.0
- description: Manifest for community-tool tests.

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


@pytest_asyncio.fixture
async def agent(tmp_path):
    save_dir = tmp_path / "alice"
    save_dir.mkdir()
    seed = MnemonicSeedSource(
        "army van defense carry jealous true garbage claim echo media make crunch"
    ).load()
    a = OpenClawAgent(
        identity=AgentIdentity.from_seed(seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=save_dir,
            initial_balance_sats=200_000,
            community_log_path=save_dir / "community.log",
            peer_log_dir=save_dir / "peer_logs",
        ),
        bt_service=StubBitTorrentService(save_dir=save_dir),
    )
    await a.start()
    # Inject a manifest pointing at this agent's own wallet address so
    # community_donate_and_join can debit it without a bech32 mismatch.
    manifest_md = MANIFEST_TEMPLATE.format(gatekeeper_address=a.wallet.address())
    a.load_manifest(manifest_md)
    yield a
    await a.stop()


@pytest_asyncio.fixture
async def two_agents(tmp_path):
    """Alice (the local agent) + bob's signed log written into alice's peer_log dir.

    Lets us write bob-as-prior-donor entries that alice's replay
    treats as legitimate foreign donations, without spinning up two
    IPv8 instances.
    """
    save_dir = tmp_path / "alice"
    save_dir.mkdir()
    peer_log_dir = save_dir / "peer_logs"

    seed_a = MnemonicSeedSource(
        "army van defense carry jealous true garbage claim echo media make crunch"
    ).load()
    alice = OpenClawAgent(
        identity=AgentIdentity.from_seed(seed_a, network="TESTNET"),
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
    await alice.start()

    # Create bob as a SignedAppendOnlyLog writing into alice's peer-log
    # cache as if pulled via the redteam pull loop.
    from identity.openclaw_identity import OpenClawIdentity
    from redteam.primitives.signed_log import SignedAppendOnlyLog

    seed_b = MnemonicSeedSource(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).load()
    bob_identity = AgentIdentity.from_seed(seed_b, network="TESTNET")
    bob_oc_identity = OpenClawIdentity.from_agent_identity(bob_identity)
    bob_log_path = peer_log_dir / f"{bob_oc_identity.identity_hash}.jsonl"
    bob_log_path.parent.mkdir(parents=True, exist_ok=True)

    bob_log = SignedAppendOnlyLog(bob_oc_identity, str(bob_log_path))

    manifest_md = MANIFEST_TEMPLATE.format(gatekeeper_address=alice.wallet.address())
    alice.load_manifest(manifest_md)

    yield alice, bob_oc_identity, bob_log, manifest_md
    await alice.stop()


# ---------------------------------------------------------------------------
# community_treasury_balance + community_member_count
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_treasury_returns_no_manifest_error_before_manifest(tmp_path):
    save_dir = tmp_path / "x"
    save_dir.mkdir()
    a = OpenClawAgent(
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
    await a.start()
    try:
        tools = build_tools(a)
        result = await tools.dispatch("community_treasury_balance", {})
        assert result == {"error": "no_manifest_loaded"}
        result2 = await tools.dispatch("community_member_count", {})
        assert result2 == {"error": "no_manifest_loaded"}
    finally:
        await a.stop()


@pytest.mark.asyncio
async def test_treasury_empty_at_genesis_with_manifest_loaded(agent):
    tools = build_tools(agent)
    result = await tools.dispatch("community_treasury_balance", {})
    assert result["balance_sats"] == 0
    assert result["member_count"] == 0
    assert result["seedbox_count"] == 1
    assert result["pending_purchases"] == 0
    assert result["threshold_active"] is False
    assert result["my_membership_status"] == "outsider"


@pytest.mark.asyncio
async def test_member_count_returns_membership_view(agent):
    tools = build_tools(agent)
    result = await tools.dispatch("community_member_count", {})
    assert result == {
        "member_count": 0,
        "my_membership_status": "outsider",
        "threshold_active": False,
    }


# ---------------------------------------------------------------------------
# community_donate_and_join — write own donation_intent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_donate_writes_intent_and_admits_self(agent):
    tools = build_tools(agent)
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})
    assert "entry_hash" in result
    assert result["amount_sats"] == 50_000

    # Replay sees the entry; we're a member; treasury holds our donation.
    state = await tools.dispatch("community_treasury_balance", {})
    assert state["balance_sats"] == 50_000
    assert state["member_count"] == 1
    assert state["my_membership_status"] == "admitted"

    # Wallet debited by the same amount.
    balance = await tools.dispatch("wallet_balance", {})
    assert balance == 200_000 - 50_000


@pytest.mark.asyncio
async def test_donate_rejects_below_min_sats(agent):
    tools = build_tools(agent)
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": 5_000})
    assert "error" in result and "min_sats" in result["error"]
    # Wallet untouched on rejection.
    balance = await tools.dispatch("wallet_balance", {})
    assert balance == 200_000


@pytest.mark.asyncio
async def test_donate_rejects_above_bootstrap_cap(agent):
    tools = build_tools(agent)
    # bootstrap_cap_sats = 100_000 in fixture
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": 150_000})
    assert "error" in result and "cap" in result["error"]


@pytest.mark.asyncio
async def test_donate_rejects_double_join(agent):
    tools = build_tools(agent)
    first = await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})
    assert "entry_hash" in first
    second = await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})
    assert second == {"error": "already_admitted"}


@pytest.mark.asyncio
async def test_donate_rejects_non_int_amount(agent):
    tools = build_tools(agent)
    # The Tool schema would reject this in production via JSON-schema
    # validation; but dispatch passes through, so the function-level
    # guard runs and surfaces a clean error.
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": -1})
    assert "error" in result


@pytest.mark.asyncio
async def test_donate_when_prior_donor_caps_to_running_average(two_agents):
    """Alice joins after bob donated 60_000 — her ceiling is 60_000."""
    alice, bob_id, bob_log, manifest_md = two_agents
    from agent.community_state import replay_community
    from protocol.manifest import parse_manifest
    manifest = parse_manifest(manifest_md)

    # Bob writes a 60k donation_intent into his (alice's-cached) peer log.
    bob_log.append_event(
        reporter_id=bob_id.identity_hash,
        subject_id=bob_id.identity_hash,
        action="donation_intent",
        details={
            "network_id_hex": manifest.network_id.hex(),
            "amount_sats": 60_000,
        },
    )

    tools = build_tools(alice)
    # Alice tries to donate 80_000 — exceeds bob's running-avg cap of 60_000.
    rejected = await tools.dispatch("community_donate_and_join", {"amount_sats": 80_000})
    assert "error" in rejected and "cap" in rejected["error"]

    # Alice donates 60_000 — accepted.
    ok = await tools.dispatch(
        "community_donate_and_join", {"amount_sats": 60_000}
    )
    assert "entry_hash" in ok

    state = await tools.dispatch("community_treasury_balance", {})
    assert state["balance_sats"] == 60_000 + 60_000
    assert state["member_count"] == 2


# ---------------------------------------------------------------------------
# community_log_list_recent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_log_list_recent_empty_when_no_entries(agent):
    tools = build_tools(agent)
    out = await tools.dispatch("community_log_list_recent", {"limit": 50})
    assert out == []


@pytest.mark.asyncio
async def test_log_list_recent_returns_own_donation_with_accepted_flag(agent):
    tools = build_tools(agent)
    await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})
    out = await tools.dispatch("community_log_list_recent", {"limit": 10})
    assert len(out) == 1
    assert out[0]["action"] == "donation_intent"
    assert out[0]["amount_sats"] == 50_000
    assert out[0]["accepted"] is True
    assert out[0]["reporter_id"] == agent.community_reporter_id


@pytest.mark.asyncio
async def test_log_list_recent_returns_empty_before_manifest(tmp_path):
    save_dir = tmp_path / "x"
    save_dir.mkdir()
    a = OpenClawAgent(
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
    await a.start()
    try:
        tools = build_tools(a)
        out = await tools.dispatch("community_log_list_recent", {"limit": 50})
        assert out == []
    finally:
        await a.stop()


# ---------------------------------------------------------------------------
# seedbox_purchase_propose
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_purchase_propose_rejected_when_not_admitted(agent):
    """A fresh agent that hasn't donated yet can't propose a purchase."""
    tools = build_tools(agent)
    result = await tools.dispatch("seedbox_purchase_propose", {})
    assert result == {"error": "not_admitted"}


@pytest.mark.asyncio
async def test_purchase_propose_rejected_when_threshold_not_active(agent):
    """Alice donates and becomes member #1; threshold (>3*1) not yet tripped."""
    tools = build_tools(agent)
    await tools.dispatch("community_donate_and_join", {"amount_sats": 60_000})
    result = await tools.dispatch("seedbox_purchase_propose", {})
    assert result == {"error": "threshold_not_active"}


@pytest.mark.asyncio
async def test_purchase_propose_accepted_when_threshold_tripped(two_agents):
    """4 members at seedbox_count=1 → threshold tripped. Alice's purchase accepted."""
    alice, bob_id, bob_log, manifest_md = two_agents
    from protocol.manifest import parse_manifest
    manifest = parse_manifest(manifest_md)
    nid = manifest.network_id.hex()

    # Three peer donors so alice is member #4. We seed peer-log entries
    # under three distinct OpenClawIdentity hashes — pretend three peers
    # donated; the actual signed_log identity binding is per-file, so
    # write each into its own peer_log file.
    from identity.openclaw_identity import OpenClawIdentity
    from identity.seed import Seed
    from redteam.primitives.signed_log import SignedAppendOnlyLog

    peer_log_dir = alice.config.peer_log_dir
    for i, mnemonic in enumerate([
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ]):
        seed = MnemonicSeedSource(mnemonic).load()
        peer_identity = AgentIdentity.from_seed(seed, network="TESTNET")
        oc = OpenClawIdentity.from_agent_identity(peer_identity)
        log_path = peer_log_dir / f"{oc.identity_hash}.jsonl"
        peer_log = SignedAppendOnlyLog(oc, str(log_path))
        # Each donor pays 60k → running-avg cap stays at 60k.
        peer_log.append_event(
            reporter_id=oc.identity_hash,
            subject_id=oc.identity_hash,
            action="donation_intent",
            details={"network_id_hex": nid, "amount_sats": 60_000},
        )

    tools = build_tools(alice)
    # Alice donates last → 4 members, threshold tripped (>3*1).
    await tools.dispatch("community_donate_and_join", {"amount_sats": 60_000})

    state = await tools.dispatch("community_treasury_balance", {})
    assert state["member_count"] == 4
    assert state["balance_sats"] == 4 * 60_000
    assert state["threshold_active"] is True

    # Alice proposes the purchase. Default cost = manifest's 50_000.
    result = await tools.dispatch("seedbox_purchase_propose", {})
    assert "entry_hash" in result
    assert result["cost_sats"] == 50_000

    after = await tools.dispatch("community_treasury_balance", {})
    assert after["balance_sats"] == 4 * 60_000 - 50_000
    assert after["pending_purchases"] == 1


@pytest.mark.asyncio
async def test_purchase_propose_rejects_wrong_cost(two_agents):
    alice, bob_id, bob_log, manifest_md = two_agents
    from protocol.manifest import parse_manifest
    manifest = parse_manifest(manifest_md)
    nid = manifest.network_id.hex()

    # Seed 3 peer donors so alice can become member #4.
    from identity.openclaw_identity import OpenClawIdentity
    from redteam.primitives.signed_log import SignedAppendOnlyLog

    peer_log_dir = alice.config.peer_log_dir
    for mnemonic in [
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    ]:
        seed = MnemonicSeedSource(mnemonic).load()
        peer_identity = AgentIdentity.from_seed(seed, network="TESTNET")
        oc = OpenClawIdentity.from_agent_identity(peer_identity)
        log_path = peer_log_dir / f"{oc.identity_hash}.jsonl"
        peer_log = SignedAppendOnlyLog(oc, str(log_path))
        peer_log.append_event(
            reporter_id=oc.identity_hash,
            subject_id=oc.identity_hash,
            action="donation_intent",
            details={"network_id_hex": nid, "amount_sats": 60_000},
        )

    tools = build_tools(alice)
    await tools.dispatch("community_donate_and_join", {"amount_sats": 60_000})
    # Manifest says 50_000; alice proposes 30_000.
    result = await tools.dispatch("seedbox_purchase_propose", {"cost_sats": 30_000})
    assert "error" in result and "manifest.seedbox_cost_sats" in result["error"]


@pytest.mark.asyncio
async def test_deprecated_tool_is_still_dispatchable(agent):
    """seedbox_donate_and_join still appears in the registry — deprecated but
    available so existing LLM prompts don't break mid-flight."""
    tools = build_tools(agent)
    assert "seedbox_donate_and_join" in tools.names()
    # Spec carries the DEPRECATED prefix.
    specs = {s["function"]["name"]: s for s in tools.specs()}
    assert specs["seedbox_donate_and_join"]["function"]["description"].startswith("DEPRECATED")
