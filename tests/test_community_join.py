"""Phase-5 admission tests: COMMUNITY_JOIN_REQUEST wire path.

Two IPv8-connected agents, each with their own SignedAppendOnlyLog +
PeerLog, both holding the same network manifest. Joiner ships a signed
donation_intent over the new wire message; gatekeeper accepts iff the
entry passes signature/identity/cap checks against its own community
replay.

Bypasses the legacy ``DonationVerifier`` path entirely.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.peer import Peer

from agent import AgentConfig, OpenClawAgent, build_tools
from communication.bittorrent import StubBitTorrentService
from communication.community import (
    CommunityJoinRequestPayload,
    CommunityJoinResponsePayload,
)
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol import StubLLMClient


MANIFEST_TEMPLATE = """\
# Identity

- name: community_join_test
- version: 1.0.0
- description: Phase-5 admission wire-path test fixture.

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


# ---------------------------------------------------------------------------
# Wire-shape unit tests (no IPv8 needed)
# ---------------------------------------------------------------------------


def test_community_join_request_payload_msg_id():
    assert CommunityJoinRequestPayload.msg_id == 10
    assert CommunityJoinRequestPayload.format_list == ["varlenH"]
    assert CommunityJoinRequestPayload.names == ["signed_entry"]


def test_community_join_response_payload_msg_id():
    assert CommunityJoinResponsePayload.msg_id == 11
    assert CommunityJoinResponsePayload.format_list == ["?", "varlenH"]
    assert CommunityJoinResponsePayload.names == ["accepted", "reason"]


# ---------------------------------------------------------------------------
# End-to-end fixture: two real IPv8-connected agents
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def alice_and_bob(tmp_path):
    """Alice (founder, has a donation already) + Bob (wants to join)."""
    a_dir = tmp_path / "alice"
    a_dir.mkdir()
    b_dir = tmp_path / "bob"
    b_dir.mkdir()

    alice_seed = MnemonicSeedSource(
        "army van defense carry jealous true garbage claim echo media make crunch"
    ).load()
    bob_seed = MnemonicSeedSource(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).load()

    alice = OpenClawAgent(
        identity=AgentIdentity.from_seed(alice_seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=a_dir,
            initial_balance_sats=200_000,
            community_log_path=a_dir / "community.log",
            peer_log_dir=a_dir / "peer_logs",
        ),
        bt_service=StubBitTorrentService(save_dir=a_dir),
    )
    bob = OpenClawAgent(
        identity=AgentIdentity.from_seed(bob_seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=b_dir,
            initial_balance_sats=200_000,
            community_log_path=b_dir / "community.log",
            peer_log_dir=b_dir / "peer_logs",
        ),
        bt_service=StubBitTorrentService(save_dir=b_dir),
    )

    await alice.start()
    await bob.start()

    # Cross-introduce on the bootstrap community so wire messages flow.
    alice.seedbox.network.add_verified_peer(
        Peer(bob.seedbox.my_peer.public_key, address=bob.address),
    )
    bob.seedbox.network.add_verified_peer(
        Peer(alice.seedbox.my_peer.public_key, address=alice.address),
    )

    # Both agents load the same manifest (alice's address as gatekeeper).
    manifest_md = MANIFEST_TEMPLATE.format(gatekeeper_address=alice.wallet.address())
    alice.load_manifest(manifest_md)
    bob.load_manifest(manifest_md)

    # Alice is the founder — she donates first so she's an admitted member
    # before bob asks to join.
    a_tools = build_tools(alice)
    await a_tools.dispatch("community_donate_and_join", {"amount_sats": 80_000})

    yield alice, bob

    await alice.stop()
    await bob.stop()


# ---------------------------------------------------------------------------
# End-to-end admission
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_community_join_accepts_valid_donation_intent(alice_and_bob):
    """Bob signs + ships a 60_000-sat donation_intent; Alice accepts."""
    alice, bob = alice_and_bob
    bob_tools = build_tools(bob)

    result = await bob_tools.dispatch(
        "community_join_via_peer",
        {
            "gatekeeper_mid": alice.seedbox.my_peer.mid.hex(),
            "amount_sats": 60_000,
            "timeout_s": 5.0,
        },
    )

    assert result["accepted"] is True, f"join rejected: {result.get('reason', result)}"
    assert result["amount_sats"] == 60_000
    assert isinstance(result.get("entry_hash"), str)

    # Alice's PeerLog now caches bob's entry → her replay sees 2 members.
    a_state = alice.community_state()
    assert a_state is not None
    assert a_state.member_count == 2
    assert alice.community_reporter_id in a_state.members
    assert bob.community_reporter_id in a_state.members
    assert a_state.balance_sats == 80_000 + 60_000


@pytest.mark.asyncio
async def test_community_join_rejected_above_running_average_cap(alice_and_bob):
    """Alice donated 80_000 (the only prior). Bob tries 90_000 — cap is 80k.

    Phase 5 ships entries via JOIN_REQUEST, NOT via the pull loop yet
    (Phase 6 wires that). So Bob's local view doesn't see Alice's entry
    until Alice ships it explicitly. We simulate that here by hand-
    seeding Alice's entry into Bob's peer_log cache — exactly what the
    pull loop will do in Phase 6.
    """
    alice, bob = alice_and_bob
    # Push Alice's single donation entry into Bob's peer_log so his
    # local replay sees Alice as the only prior donor.
    for entry in alice.community_log.read_entries():
        bob.peer_log.accept_entry(entry)

    bob_tools = build_tools(bob)
    result = await bob_tools.dispatch(
        "community_join_via_peer",
        {
            "gatekeeper_mid": alice.seedbox.my_peer.mid.hex(),
            "amount_sats": 90_000,
            "timeout_s": 5.0,
        },
    )

    # The pre-check inside community_donate_and_join rejects the write
    # locally — the wire request never goes out.
    assert "error" in result
    assert "cap" in result["error"]


@pytest.mark.asyncio
async def test_community_join_response_carries_reason_text(alice_and_bob):
    """When gatekeeper rejects, the response.reason field surfaces upward."""
    alice, bob = alice_and_bob

    # Bypass bob's tool layer and ship a malformed entry directly so the
    # gatekeeper exercises the "rejected_by_community_rules" path.
    forged_entry = {
        "version": 2,
        "kind": "self",
        "action": "donation_intent",
        # reporter_id that doesn't match any signed key — peer_log will
        # reject signature/identity binding before community-rules even run.
        "reporter_id": "ff" * 32,
        "subject_id": "ff" * 32,
        "timestamp": "2026-05-14T12:00:00+00:00",
        "details": {
            "network_id_hex": alice.network_manifest.network_id.hex(),
            "amount_sats": 50_000,
        },
        "details_hash": "00" * 32,
        "evidence": {},
        "evidence_hash": "00" * 32,
        "severity": 0,
        "previous_hash": "GENESIS",
        "reporter_pubkey": "00" * 32,
        "signature": "00" * 64,
        "entry_hash": "00" * 32,
    }

    future = bob.seedbox.request_community_join(
        Peer(alice.seedbox.my_peer.public_key, address=alice.address),
        forged_entry,
    )
    accepted, reason = await asyncio.wait_for(future, timeout=5.0)
    assert accepted is False
    assert isinstance(reason, str) and reason  # non-empty diagnostic string


@pytest.mark.asyncio
async def test_community_join_callback_returns_no_manifest_when_unloaded(tmp_path):
    """An agent without a manifest can't admit anyone — rejects with reason."""
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
        # No manifest loaded → callback rejects without touching peer_log.
        accepted, reason = a._handle_community_join(
            peer=None,
            entry={"action": "donation_intent"},
        )
        assert accepted is False
        assert reason == "no_manifest_loaded"
    finally:
        await a.stop()


# ---------------------------------------------------------------------------
# Regression: a timed-out wire ack must NOT look like a failure.
#
# v5.2 admission is decided by signed-log replay, not by the IPv8
# CommunityJoinResponse. Caught live in the seek_cc 16:07 run: every
# joiner's community_join_via_peer blocked the full 30s on a wire reply
# that never arrived, holding the cross-agent LLM turn lock and stalling
# the whole scenario — even though the donation_intent was already
# written locally and replicating. The tool must (a) bound the wait low
# and (b) return a non-error envelope so the LLM treats the turn as done
# instead of retrying (a retry re-debits the wallet + writes a duplicate
# intent that replay rejects).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_community_join_timeout_returns_pending_not_error(alice_and_bob, monkeypatch):
    alice, bob = alice_and_bob

    # Force the wire reply to never arrive: replace request_community_join
    # with one that ships nothing and returns a future that never resolves.
    never = asyncio.get_event_loop().create_future()

    def _never_resolves(_gatekeeper, _entry):
        return never

    monkeypatch.setattr(
        bob.seedbox, "request_community_join", _never_resolves
    )

    bob_tools = build_tools(bob)
    result = await bob_tools.dispatch(
        "community_join_via_peer",
        {
            "gatekeeper_mid": alice.seedbox.my_peer.mid.hex(),
            "amount_sats": 60_000,
            "timeout_s": 0.2,   # tiny — we only care about the timeout branch
        },
    )

    # NOT a failure envelope — the local write succeeded, admission
    # proceeds via replication. The LLM must not see an `error` key.
    assert "error" not in result, f"timeout wrongly surfaced as error: {result}"
    assert result["accepted"] is None
    assert result["reason"] == "wire_reply_timeout_admission_via_replication_pending"
    assert isinstance(result["entry_hash"], str)
    assert result["amount_sats"] == 60_000
    # The note must steer the LLM away from re-calling (wallet re-debit).
    assert "do NOT" in result["note"]

    # The donation_intent really was written locally despite the timeout —
    # i.e. bob admitted himself via his own log; replay will confirm once
    # peers pull it.
    entry = next(
        e for e in reversed(bob.community_log.read_entries())
        if e.get("entry_hash") == result["entry_hash"]
    )
    assert entry["action"] == "donation_intent"
    assert entry["details"]["amount_sats"] == 60_000


def test_community_join_default_timeout_is_bounded_low():
    """The default timeout must stay small — it runs under the
    cross-agent LLM turn lock, so a large default re-introduces the
    scenario-wide stall this regression fixes."""
    import inspect
    from agent.tools import build_tools as _bt  # noqa: F401  (import-site check)
    # The signature default lives on the inner closure; assert via the
    # source so we don't have to construct an agent here.
    import agent.tools as _tools_mod
    src = inspect.getsource(_tools_mod.build_tools)
    assert "timeout_s: float = 8.0" in src, (
        "community_join_via_peer default timeout changed; keep it low "
        "(<=10s) — it blocks the cross-agent LLM lock"
    )
