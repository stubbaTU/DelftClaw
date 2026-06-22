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
    replay_community,
)
from protocol.manifest import parse_manifest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


REPO_ROOT = Path(__file__).resolve().parent.parent


MANIFEST_TEXT = """\
# Identity

- name: admission_test
- version: 1.0.0
- description: Fixture network for community_state replay tests.

# Admission

- gatekeeper_address: dclaw1abc
- min_sats: 10000
- min_confirmations: 0
- bootstrap_cap_sats: 100000

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


def _donation(*, reporter, amount, ts, eh, nid, wallet=None):
    extra = {"amount_sats": amount}
    if wallet is not None:
        extra["wallet_address"] = wallet
    return _entry(
        action="donation_intent",
        reporter=reporter,
        network_id_hex=nid,
        timestamp=ts,
        entry_hash=eh,
        details_extra=extra,
    )


def _payment(*, reporter, to_wallet, amount, ts, eh, nid):
    return _entry(
        action="payment",
        reporter=reporter,
        network_id_hex=nid,
        timestamp=ts,
        entry_hash=eh,
        details_extra={"to_wallet": to_wallet, "amount_sats": amount},
    )


# ---------------------------------------------------------------------------
# Empty / unrelated inputs
# ---------------------------------------------------------------------------


def test_replay_empty_yields_no_members(manifest):
    state = replay_community(manifest, [])
    assert state == CommunityState(
        members=frozenset(),
        donations=(),
        balance_sats=0,
    )
    assert state.member_count == 0


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


# ---------------------------------------------------------------------------
# Payment ledger (peer-to-peer transfers replayed into balances)
# ---------------------------------------------------------------------------


def _two_members(manifest):
    """Two admitted members alice/bob with known wallets; returns (nid, entries)."""
    nid = manifest.network_id.hex()
    return nid, [
        _donation(reporter="alice", amount=80_000, ts="t1", eh="d1", nid=nid, wallet="w_alice"),
        _donation(reporter="bob", amount=80_000, ts="t2", eh="d2", nid=nid, wallet="w_bob"),
    ]


def test_payment_between_members_updates_balances(manifest):
    nid, base = _two_members(manifest)
    state = replay_community(manifest, base + [
        _payment(reporter="alice", to_wallet="w_bob", amount=5_000, ts="t3", eh="p1", nid=nid),
        _payment(reporter="bob", to_wallet="w_alice", amount=2_000, ts="t4", eh="p2", nid=nid),
    ])
    assert len(state.payments) == 2
    assert state.balances == {"w_alice": -3_000, "w_bob": 3_000}
    # Treasury (donations) is untouched by payments.
    assert state.balance_sats == 160_000


def test_payment_to_non_member_wallet_rejected(manifest):
    nid, base = _two_members(manifest)
    state = replay_community(manifest, base + [
        _payment(reporter="alice", to_wallet="w_charlie", amount=1_000, ts="t3", eh="p1", nid=nid),
    ])
    assert state.payments == ()
    assert state.balances == {"w_alice": 0, "w_bob": 0}


def test_payment_from_non_member_rejected(manifest):
    nid, base = _two_members(manifest)
    state = replay_community(manifest, base + [
        _payment(reporter="mallory", to_wallet="w_bob", amount=1_000, ts="t3", eh="p1", nid=nid),
    ])
    assert state.payments == ()


def test_self_payment_rejected(manifest):
    nid, base = _two_members(manifest)
    state = replay_community(manifest, base + [
        _payment(reporter="alice", to_wallet="w_alice", amount=1_000, ts="t3", eh="p1", nid=nid),
    ])
    assert state.payments == ()


def test_payment_nonpositive_amount_rejected(manifest):
    nid, base = _two_members(manifest)
    state = replay_community(manifest, base + [
        _payment(reporter="alice", to_wallet="w_bob", amount=0, ts="t3", eh="p1", nid=nid),
        _payment(reporter="alice", to_wallet="w_bob", amount=-5, ts="t4", eh="p2", nid=nid),
    ])
    assert state.payments == ()


def test_payment_before_recipient_admitted_rejected(manifest):
    """Time-ordered replay: a payment to a wallet whose donation comes later
    is rejected (recipient not yet a known member wallet at that point)."""
    nid = manifest.network_id.hex()
    state = replay_community(manifest, [
        _donation(reporter="alice", amount=80_000, ts="t1", eh="d1", nid=nid, wallet="w_alice"),
        _payment(reporter="alice", to_wallet="w_bob", amount=1_000, ts="t2", eh="p1", nid=nid),
        _donation(reporter="bob", amount=80_000, ts="t3", eh="d2", nid=nid, wallet="w_bob"),
    ])
    assert state.payments == ()
