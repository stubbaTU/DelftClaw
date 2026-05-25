"""Stop-predicate unit tests.

  - resolve(spec): handles bare names, parameterised forms, rejects unknown.
  - each predicate returns True/False against a synthetic snapshot.
  - wallet delta predicates compare against state recorded across ticks.
"""

from __future__ import annotations

import pytest

from deploy import stop_predicates as sp


# ---------------------------------------------------------------------------
# Synthetic snapshot helpers
# ---------------------------------------------------------------------------

def _snap(*, peers=0, torrents=None, balance=0, agent_id="agent-1",
          confirmed_received_sats=None, confirmed_sent_sats=None,
          unconfirmed_sent_sats=None) -> dict:
    wallet = {"address": "tb1qx", "balance_sats": balance}
    if confirmed_received_sats is not None:
        wallet["confirmed_received_sats"] = confirmed_received_sats
    if confirmed_sent_sats is not None:
        wallet["confirmed_sent_sats"] = confirmed_sent_sats
    if unconfirmed_sent_sats is not None:
        wallet["unconfirmed_sent_sats"] = unconfirmed_sent_sats
    return {
        "agent": {"agent_id": agent_id},
        "peers": [{"mid_hex": f"aa{i:02d}" * 10, "address": ["127.0.0.1", 8000 + i]}
                  for i in range(peers)],
        "torrents": torrents or [],
        "wallet": wallet,
    }


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

def test_resolve_bare_name():
    p = sp.resolve("never")
    assert p(_snap()) is False


def test_resolve_factory_with_arg():
    p = sp.resolve("peer_count_gte_N(n=2)")
    assert p(_snap(peers=1)) is False
    assert p(_snap(peers=2)) is True
    assert p(_snap(peers=5)) is True


def test_resolve_unknown_name_raises():
    with pytest.raises(sp.UnknownPredicate):
        sp.resolve("not_a_real_predicate")


def test_resolve_args_on_bare_predicate_raises():
    with pytest.raises(sp.UnknownPredicate):
        sp.resolve("never(n=1)")


def test_resolve_handles_default_args():
    # peer_count_gte_N defaults to n=1
    p = sp.resolve("peer_count_gte_N()")
    assert p(_snap(peers=0)) is False
    assert p(_snap(peers=1)) is True


# ---------------------------------------------------------------------------
# Predicate behaviour
# ---------------------------------------------------------------------------

def test_never_is_always_false():
    p = sp.resolve("never")
    assert p(_snap(peers=99, torrents=[{"progress": 1.0}], balance=10_000_000)) is False


def test_torrent_progress_gte_1_triggers_at_completion():
    p = sp.resolve("torrent_progress_gte_1")
    assert p(_snap(torrents=[{"progress": 0.5}])) is False
    assert p(_snap(torrents=[{"progress": 0.99}])) is False
    assert p(_snap(torrents=[{"progress": 1.0}])) is True
    # Mixed bag: any one complete is enough.
    assert p(_snap(torrents=[{"progress": 0.1}, {"progress": 1.0}])) is True


def test_torrent_progress_no_torrents_yields_false():
    p = sp.resolve("torrent_progress_gte_1")
    assert p(_snap()) is False


def test_wallet_received_sats_uses_baseline():
    snap0 = _snap(balance=10_000)
    sp.set_baseline("agent-1", snap0)

    p = sp.resolve("wallet_received_sats(min_sats=5000)")
    # Balance unchanged -> False.
    assert p(_snap(balance=10_000)) is False
    # Below threshold delta -> False.
    assert p(_snap(balance=14_000)) is False
    # At/above threshold delta -> True.
    assert p(_snap(balance=15_000)) is True
    assert p(_snap(balance=100_000)) is True


def test_wallet_received_sats_without_baseline_treats_first_snapshot_as_baseline():
    p = sp.resolve("wallet_received_sats(min_sats=1)")
    # No baseline set; predicate compares against snapshot itself -> 0 delta.
    assert p(_snap(agent_id="brand-new", balance=999)) is False


def test_wallet_received_sats_prefers_confirmed_received_total():
    snap0 = _snap(
        agent_id="receiver-with-spend",
        balance=10_000,
        confirmed_received_sats=10_000,
    )
    sp.set_baseline("receiver-with-spend", snap0)

    p = sp.resolve("wallet_received_sats(min_sats=20_000)")
    # Net balance is unchanged after spending the admission funds and later
    # receiving a payment, but the monotonic receive total has increased.
    assert p(_snap(
        agent_id="receiver-with-spend",
        balance=10_000,
        confirmed_received_sats=30_000,
    )) is True


def test_wallet_received_sats_confirmed_received_below_threshold():
    sp.set_baseline("receiver-below", _snap(
        agent_id="receiver-below",
        balance=10_000,
        confirmed_received_sats=10_000,
    ))

    p = sp.resolve("wallet_received_sats(min_sats=20_000)")
    assert p(_snap(
        agent_id="receiver-below",
        balance=29_000,
        confirmed_received_sats=29_000,
    )) is False


def test_bitcoin_sent_sats_triggers_after_drop_from_peak():
    sp.set_baseline("sender-1", _snap(agent_id="sender-1", balance=0))
    p = sp.resolve("bitcoin_sent_sats(min_sats=10000)")

    assert p(_snap(agent_id="sender-1", balance=0)) is False
    assert p(_snap(agent_id="sender-1", balance=5_000_000_000)) is False
    assert p(_snap(agent_id="sender-1", balance=4_999_995_001)) is False
    assert p(_snap(agent_id="sender-1", balance=4_999_990_000)) is True


def test_bitcoin_sent_sats_without_peak_treats_first_snapshot_as_peak():
    p = sp.resolve("bitcoin_sent_sats(min_sats=1)")
    assert p(_snap(agent_id="new-sender", balance=100_000)) is False


def test_bitcoin_confirmed_sent_sats_uses_baseline():
    sp.set_baseline("confirmed-sender", _snap(
        agent_id="confirmed-sender",
        confirmed_sent_sats=50_000,
    ))

    p = sp.resolve("bitcoin_confirmed_sent_sats(min_sats=20_000)")
    assert p(_snap(
        agent_id="confirmed-sender",
        confirmed_sent_sats=69_999,
    )) is False
    assert p(_snap(
        agent_id="confirmed-sender",
        confirmed_sent_sats=70_000,
    )) is True


def test_bitcoin_confirmed_sent_sats_ignores_unconfirmed_sends():
    sp.set_baseline("unconfirmed-sender", _snap(
        agent_id="unconfirmed-sender",
        confirmed_sent_sats=0,
        unconfirmed_sent_sats=0,
    ))

    p = sp.resolve("bitcoin_confirmed_sent_sats(min_sats=20_000)")
    assert p(_snap(
        agent_id="unconfirmed-sender",
        confirmed_sent_sats=0,
        unconfirmed_sent_sats=20_000,
    )) is False


def test_bitcoin_confirmed_sent_sats_without_baseline_treats_first_snapshot_as_baseline():
    p = sp.resolve("bitcoin_confirmed_sent_sats(min_sats=1)")
    assert p(_snap(agent_id="new-confirmed-sender", confirmed_sent_sats=20_000)) is False


def test_known_predicate_names_lists_all_predicates():
    names = sp.known_predicate_names()
    assert set(names) >= {"never", "torrent_progress_gte_1",
                          "peer_count_gte_N", "wallet_received_sats",
                          "bitcoin_sent_sats",
                          "bitcoin_confirmed_sent_sats"}
