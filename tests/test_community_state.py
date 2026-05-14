"""Tests for ``agent.community_state.replay_community``.

The replay is a pure fold over signed-log entry dicts. Tests build
small entry lists with the same shape ``SignedAppendOnlyLog._build_entry``
produces and assert the resulting ``CommunityState`` directly — no
real signed-log instances, no I/O, no IPv8.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.community_state import (
    CommunityState,
    DonationIntent,
    SeedboxProvisioned,
    SeedboxPurchaseIntent,
    replay_community,
)
from protocol.manifest import parse_manifest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


REPO_ROOT = Path(__file__).resolve().parent.parent


MANIFEST_TEXT = """\
# Identity

- name: seek_cc_test
- version: 1.0.0
- description: Fixture network for community_state replay tests.

# Admission

- gatekeeper_address: dclaw1abc
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


@pytest.fixture
def manifest():
    return parse_manifest(MANIFEST_TEXT)


# A growth-disabled manifest (one of the two growth fields zero) so we
# can test the "growth disabled" branch without restructuring the rest.
MANIFEST_NO_GROWTH = MANIFEST_TEXT.replace(
    "- max_agents_per_seedbox: 3\n- seedbox_cost_sats: 50000\n", "",
)


@pytest.fixture
def manifest_no_growth():
    return parse_manifest(MANIFEST_NO_GROWTH)


def _entry(
    *,
    action: str,
    reporter: str,
    network_id_hex: str,
    timestamp: str,
    entry_hash: str,
    details_extra: dict | None = None,
) -> dict:
    """Build a signed-log-shaped entry dict for replay.

    Replay never checks signatures or chain integrity — those are
    upstream concerns. The fields the replay reads are ``action``,
    ``reporter_id``, ``timestamp``, ``entry_hash``, and ``details``.
    """
    details = {"network_id_hex": network_id_hex}
    if details_extra:
        details.update(details_extra)
    return {
        "version": 2,
        "kind": "self",
        "action": action,
        "reporter_id": reporter,
        "timestamp": timestamp,
        "entry_hash": entry_hash,
        "details": details,
    }


def _donation(*, reporter, amount, ts, eh, nid):
    return _entry(
        action="donation_intent",
        reporter=reporter,
        network_id_hex=nid,
        timestamp=ts,
        entry_hash=eh,
        details_extra={"amount_sats": amount},
    )


def _purchase(*, reporter, cost, ts, eh, nid):
    return _entry(
        action="seedbox_purchase_intent",
        reporter=reporter,
        network_id_hex=nid,
        timestamp=ts,
        entry_hash=eh,
        details_extra={"cost_sats": cost},
    )


def _provisioned(*, reporter, intent_hash, url, pubkey, ts, eh, nid):
    return _entry(
        action="seedbox_provisioned",
        reporter=reporter,
        network_id_hex=nid,
        timestamp=ts,
        entry_hash=eh,
        details_extra={
            "purchase_intent_hash": intent_hash,
            "seedbox_url": url,
            "seedbox_pubkey_hex": pubkey,
        },
    )


# ---------------------------------------------------------------------------
# Empty / unrelated inputs
# ---------------------------------------------------------------------------


def test_replay_empty_yields_genesis_only(manifest):
    state = replay_community(manifest, [])
    assert state == CommunityState(
        members=frozenset(),
        donations=(),
        purchases=(),
        provisioned=(),
        balance_sats=0,
        seedbox_count=1,
    )
    assert state.member_count == 0
    assert state.pending_purchases == 0
    assert state.threshold_active(manifest) is False


def test_replay_ignores_non_community_actions(manifest):
    """Security / accountability entries on the same log are skipped."""
    nid = manifest.network_id.hex()
    entries = [
        _entry(action="tool_execution_success", reporter="r1",
               network_id_hex=nid, timestamp="2026-01-01T00:00:00", entry_hash="h1"),
        _entry(action="log_broadcast", reporter="r2",
               network_id_hex=nid, timestamp="2026-01-01T00:01:00", entry_hash="h2"),
    ]
    state = replay_community(manifest, entries)
    assert state.member_count == 0
    assert state.balance_sats == 0


def test_replay_ignores_entries_for_other_networks(manifest):
    state = replay_community(manifest, [
        _donation(reporter="alice", amount=20_000, ts="t1", eh="h1",
                  nid="00" * 20),  # different network_id
    ])
    assert state.member_count == 0
    assert state.balance_sats == 0


# ---------------------------------------------------------------------------
# Donation acceptance + cap dynamics
# ---------------------------------------------------------------------------


def test_first_donor_can_pay_up_to_bootstrap_cap(manifest):
    nid = manifest.network_id.hex()
    # bootstrap_cap_sats=100_000 in the fixture
    state = replay_community(manifest, [
        _donation(reporter="bob", amount=80_000, ts="t1", eh="h1", nid=nid),
    ])
    assert state.member_count == 1
    assert state.balance_sats == 80_000
    assert state.donations[0].amount_sats == 80_000


def test_first_donor_above_bootstrap_cap_is_rejected(manifest):
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="whale", amount=200_000, ts="t1", eh="h1", nid=nid),
    ])
    assert state.member_count == 0
    assert state.balance_sats == 0


def test_first_donor_below_min_sats_is_rejected(manifest):
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="cheap", amount=5_000, ts="t1", eh="h1", nid=nid),
    ])
    assert state.member_count == 0


def test_second_donor_capped_at_running_average_of_priors(manifest):
    """After bob donates 80_000, charlie must pay <= 80_000."""
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="bob",     amount=80_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="charlie", amount=80_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="greedy",  amount=90_000, ts="t3", eh="h3", nid=nid),
    ])
    assert state.member_count == 2
    assert "bob" in state.members
    assert "charlie" in state.members
    assert "greedy" not in state.members
    assert state.balance_sats == 160_000


def test_cap_shrinks_with_each_smaller_donation(manifest):
    """The running average is monotonically non-increasing under this rule."""
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="d1", amount=80_000, ts="t1", eh="h1", nid=nid),  # bootstrap
        _donation(reporter="d2", amount=40_000, ts="t2", eh="h2", nid=nid),  # cap=80_000
        _donation(reporter="d3", amount=60_000, ts="t3", eh="h3", nid=nid),  # cap=60_000 (mean)
        _donation(reporter="d4", amount=70_000, ts="t4", eh="h4", nid=nid),  # cap=60_000, REJECTED
    ])
    assert state.member_count == 3
    assert "d4" not in state.members
    assert state.balance_sats == 80_000 + 40_000 + 60_000


def test_cap_never_falls_below_min_sats(manifest):
    """If the running average falls below min_sats, the cap is min_sats."""
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="d1", amount=10_000, ts="t1", eh="h1", nid=nid),  # exactly min_sats
        # avg now 10_000 == min_sats; d2 may pay min_sats.
        _donation(reporter="d2", amount=10_000, ts="t2", eh="h2", nid=nid),
    ])
    assert state.member_count == 2


def test_double_join_is_rejected(manifest):
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="bob", amount=20_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="bob", amount=20_000, ts="t2", eh="h2", nid=nid),
    ])
    assert state.member_count == 1
    assert state.balance_sats == 20_000


# ---------------------------------------------------------------------------
# Ordering / determinism
# ---------------------------------------------------------------------------


def test_replay_order_is_independent_of_input_iteration(manifest):
    nid = manifest.network_id.hex()
    entries = [
        _donation(reporter="d1", amount=80_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="d2", amount=40_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="d3", amount=60_000, ts="t3", eh="h3", nid=nid),
    ]
    forward = replay_community(manifest, entries)
    backward = replay_community(manifest, list(reversed(entries)))
    interleaved = replay_community(manifest, [entries[1], entries[2], entries[0]])
    assert forward == backward == interleaved


def test_replay_breaks_timestamp_ties_deterministically(manifest):
    """Two entries with the same timestamp sort by reporter_id then entry_hash."""
    nid = manifest.network_id.hex()
    # ts-equal donations from two different reporters
    state = replay_community(manifest, [
        _donation(reporter="zulu",  amount=80_000, ts="t1", eh="h2", nid=nid),
        _donation(reporter="alpha", amount=80_000, ts="t1", eh="h1", nid=nid),
    ])
    assert state.member_count == 2
    # alpha sorted first, so alpha's the bootstrap donor (no effect on
    # outcome here, but the order is observable in state.donations).
    assert state.donations[0].reporter_id == "alpha"
    assert state.donations[1].reporter_id == "zulu"


# ---------------------------------------------------------------------------
# Seedbox purchase intent — threshold + first-comer + treasury
# ---------------------------------------------------------------------------


def test_purchase_intent_rejected_when_threshold_not_tripped(manifest):
    """max_agents_per_seedbox=3, seedbox_count=1 → tripped at 4+ members."""
    nid = manifest.network_id.hex()
    # 3 members; threshold = 3*1 = 3; members == cap, NOT tripped.
    state = replay_community(manifest, [
        _donation(reporter="m1", amount=80_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="m2", amount=60_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="m3", amount=60_000, ts="t3", eh="h3", nid=nid),
        _purchase(reporter="m1", cost=50_000, ts="t4", eh="h4", nid=nid),
    ])
    assert state.member_count == 3
    assert state.threshold_active(manifest) is False
    assert state.purchases == ()


def test_purchase_intent_accepted_when_threshold_tripped(manifest):
    """4 members at seedbox_count=1 → threshold tripped (> 3*1)."""
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="m1", amount=80_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="m2", amount=60_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="m3", amount=60_000, ts="t3", eh="h3", nid=nid),
        _donation(reporter="m4", amount=60_000, ts="t4", eh="h4", nid=nid),
        _purchase(reporter="m1", cost=50_000, ts="t5", eh="h5", nid=nid),
    ])
    assert state.member_count == 4
    assert state.threshold_active(manifest) is True
    assert len(state.purchases) == 1
    assert state.balance_sats == 80_000 + 60_000 + 60_000 + 60_000 - 50_000
    assert state.pending_purchases == 1


def test_purchase_intent_first_comer_wins(manifest):
    """Two purchase intents race; first by sort order wins; second rejected."""
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="m1", amount=80_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="m2", amount=60_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="m3", amount=60_000, ts="t3", eh="h3", nid=nid),
        _donation(reporter="m4", amount=60_000, ts="t4", eh="h4", nid=nid),
        _purchase(reporter="m1", cost=50_000, ts="t5", eh="h5", nid=nid),
        _purchase(reporter="m2", cost=50_000, ts="t6", eh="h6", nid=nid),
    ])
    assert len(state.purchases) == 1
    assert state.purchases[0].reporter_id == "m1"
    # Treasury only debited once.
    assert state.balance_sats == 260_000 - 50_000


def test_purchase_intent_rejected_when_growth_disabled(manifest_no_growth):
    nid = manifest_no_growth.network_id.hex()
    state = replay_community(manifest_no_growth, [
        _donation(reporter="m1", amount=20_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="m2", amount=20_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="m3", amount=20_000, ts="t3", eh="h3", nid=nid),
        _donation(reporter="m4", amount=20_000, ts="t4", eh="h4", nid=nid),
        _purchase(reporter="m1", cost=50_000, ts="t5", eh="h5", nid=nid),
    ])
    assert state.threshold_active(manifest_no_growth) is False
    assert state.purchases == ()


def test_purchase_intent_rejected_when_signer_not_a_member(manifest):
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="m1", amount=80_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="m2", amount=60_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="m3", amount=60_000, ts="t3", eh="h3", nid=nid),
        _donation(reporter="m4", amount=60_000, ts="t4", eh="h4", nid=nid),
        _purchase(reporter="outsider", cost=50_000, ts="t5", eh="h5", nid=nid),
    ])
    assert state.purchases == ()


def test_purchase_intent_rejected_when_cost_mismatches_manifest(manifest):
    """The manifest declares the price; the entry must match exactly."""
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="m1", amount=80_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="m2", amount=60_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="m3", amount=60_000, ts="t3", eh="h3", nid=nid),
        _donation(reporter="m4", amount=60_000, ts="t4", eh="h4", nid=nid),
        _purchase(reporter="m1", cost=30_000, ts="t5", eh="h5", nid=nid),  # wrong price
    ])
    assert state.purchases == ()


def test_purchase_intent_rejected_when_treasury_insufficient(manifest):
    """4 small donors at exactly min_sats can't afford the seedbox."""
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="m1", amount=10_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="m2", amount=10_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="m3", amount=10_000, ts="t3", eh="h3", nid=nid),
        _donation(reporter="m4", amount=10_000, ts="t4", eh="h4", nid=nid),
        _purchase(reporter="m1", cost=50_000, ts="t5", eh="h5", nid=nid),
    ])
    assert state.balance_sats == 40_000
    assert state.purchases == ()


# ---------------------------------------------------------------------------
# Seedbox provisioned — closes a pending purchase, bumps seedbox_count
# ---------------------------------------------------------------------------


def test_provisioned_closes_pending_purchase_and_bumps_seedbox_count(manifest):
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="m1", amount=80_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="m2", amount=60_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="m3", amount=60_000, ts="t3", eh="h3", nid=nid),
        _donation(reporter="m4", amount=60_000, ts="t4", eh="h4", nid=nid),
        _purchase(reporter="m1", cost=50_000, ts="t5", eh="h5", nid=nid),
        _provisioned(reporter="m1", intent_hash="h5",
                     url="mock-seedbox-2.delftclaw.test:18769",
                     pubkey="b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
                     ts="t6", eh="h6", nid=nid),
    ])
    assert state.seedbox_count == 2
    assert state.pending_purchases == 0
    # Threshold now: 4 > 3*2 == 6 → False (room for two more members).
    assert state.threshold_active(manifest) is False


def test_provisioned_after_close_unblocks_second_purchase(manifest):
    """seedbox_count=2 means cap=6; need >6 members to trip again."""
    nid = manifest.network_id.hex()
    donations = [
        _donation(reporter=f"m{i}", amount=20_000, ts=f"t{i:02}",
                  eh=f"d{i:02}", nid=nid)
        for i in range(1, 8)  # m1..m7 — 7 members
    ]
    later = [
        _purchase(reporter="m1", cost=50_000, ts="t20", eh="p1", nid=nid),
        _provisioned(reporter="m1", intent_hash="p1",
                     url="sb2:1", pubkey="b1" * 20,
                     ts="t21", eh="v1", nid=nid),
        # After seedbox_count=2, threshold = 3*2=6; member_count=7 > 6.
        _purchase(reporter="m2", cost=50_000, ts="t22", eh="p2", nid=nid),
    ]
    state = replay_community(manifest, donations + later)
    assert state.seedbox_count == 2
    assert len(state.purchases) == 2
    assert state.pending_purchases == 1
    assert state.balance_sats == 7 * 20_000 - 2 * 50_000


def test_provisioned_rejected_without_matching_intent(manifest):
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="m1", amount=80_000, ts="t1", eh="h1", nid=nid),
        _provisioned(reporter="m1", intent_hash="nonexistent",
                     url="sb:1", pubkey="aa" * 20,
                     ts="t2", eh="v1", nid=nid),
    ])
    assert state.provisioned == ()
    assert state.seedbox_count == 1


def test_provisioned_rejected_when_signer_not_a_member(manifest):
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="m1", amount=80_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="m2", amount=60_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="m3", amount=60_000, ts="t3", eh="h3", nid=nid),
        _donation(reporter="m4", amount=60_000, ts="t4", eh="h4", nid=nid),
        _purchase(reporter="m1", cost=50_000, ts="t5", eh="h5", nid=nid),
        _provisioned(reporter="outsider", intent_hash="h5",
                     url="sb:1", pubkey="aa" * 20,
                     ts="t6", eh="v1", nid=nid),
    ])
    assert state.provisioned == ()
    assert state.seedbox_count == 1
    # The purchase still drained the treasury — it's accepted, just not
    # yet "delivered". Operator can write a follow-up provisioned event.
    assert state.pending_purchases == 1


def test_provisioned_rejected_when_already_closed(manifest):
    """A second provisioned referencing the same intent is dropped."""
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="m1", amount=80_000, ts="t1", eh="h1", nid=nid),
        _donation(reporter="m2", amount=60_000, ts="t2", eh="h2", nid=nid),
        _donation(reporter="m3", amount=60_000, ts="t3", eh="h3", nid=nid),
        _donation(reporter="m4", amount=60_000, ts="t4", eh="h4", nid=nid),
        _purchase(reporter="m1", cost=50_000, ts="t5", eh="h5", nid=nid),
        _provisioned(reporter="m1", intent_hash="h5",
                     url="sb-A:1", pubkey="aa" * 20,
                     ts="t6", eh="v1", nid=nid),
        _provisioned(reporter="m2", intent_hash="h5",
                     url="sb-B:1", pubkey="bb" * 20,
                     ts="t7", eh="v2", nid=nid),
    ])
    assert len(state.provisioned) == 1
    assert state.provisioned[0].seedbox_url == "sb-A:1"
    assert state.seedbox_count == 2


# ---------------------------------------------------------------------------
# Defensive: malformed entries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("amount", [None, "10000", 0, -1, True])
def test_donation_intent_rejects_malformed_amount(manifest, amount):
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="bob", amount=amount, ts="t1", eh="h1", nid=nid),
    ])
    assert state.member_count == 0


def test_donation_intent_rejects_missing_reporter_id(manifest):
    nid = manifest.network_id.hex()
    bad = _donation(reporter="bob", amount=20_000, ts="t1", eh="h1", nid=nid)
    bad.pop("reporter_id")
    state = replay_community(manifest, [bad])
    assert state.member_count == 0
