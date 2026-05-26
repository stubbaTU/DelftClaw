from __future__ import annotations

from deploy.watchdog import _classify_openclaw_turn, _snapshot_for_prompt


def test_classify_openclaw_turn_flags_literal_error() -> None:
    ok, summary, reason = _classify_openclaw_turn(
        subprocess_ok=True,
        stdout='{"payloads":[{"text":"ERROR","mediaUrl":null}]}',
        stderr="",
    )
    assert ok is False
    assert summary.semantic_error == "openclaw_semantic_error:literal_ERROR"
    assert reason == "openclaw_semantic_error:literal_ERROR"


def test_classify_openclaw_turn_allows_empty_wait() -> None:
    ok, summary, reason = _classify_openclaw_turn(
        subprocess_ok=True,
        stdout='{"payloads":[]}',
        stderr="",
    )
    assert ok is True
    assert summary.assistant_text == ""
    assert reason is None


def test_classify_openclaw_turn_preserves_subprocess_failure() -> None:
    ok, summary, reason = _classify_openclaw_turn(
        subprocess_ok=False,
        stdout='{"payloads":[{"text":"hello"}]}',
        stderr="provider unavailable",
    )
    assert ok is False
    assert summary.assistant_text == "hello"
    assert reason == "provider unavailable"


def test_snapshot_for_prompt_adds_authoritative_stop_status_without_mutating() -> None:
    snapshot = {"wallet": {"confirmed_received_sats": 20_000}}

    out = _snapshot_for_prompt(
        snapshot,
        stop_predicate="wallet_received_sats(min_sats=20000)",
        stop_predicate_value=False,
    )

    assert "stop_predicate" not in snapshot
    assert out["wallet"]["confirmed_received_sats"] == 20_000
    assert out["stop_predicate"] == {
        "predicate": "wallet_received_sats(min_sats=20000)",
        "satisfied": False,
        "authority": "watchdog_evaluated_against_scenario_baseline",
    }


def test_regtest_guidance_tells_alice_to_send_when_bob_wallet_known() -> None:
    out = _snapshot_for_prompt(
        {
            "wallet": {"confirmed_sent_sats": 0, "unconfirmed_sent_sats": 0},
            "peers": [{"mid_hex": "bobmid", "wallet_address": "bcrt1qbob"}],
        },
        stop_predicate="bitcoin_confirmed_sent_sats(min_sats=20000)",
        stop_predicate_value=False,
        scenario_name="regtest_transfer",
        agent_name="alice",
    )

    guidance = out["next_action_guidance"]
    assert guidance["phase"] == "send_payment"
    assert guidance["tool_call"] == {
        "name": "btc_send",
        "arguments": {"to_address": "bcrt1qbob", "amount_sat": 20_000},
    }
    assert "peer_add" in guidance["forbidden"]


def test_regtest_guidance_tells_alice_to_mine_after_unconfirmed_send() -> None:
    out = _snapshot_for_prompt(
        {
            "wallet": {"confirmed_sent_sats": 0, "unconfirmed_sent_sats": 20_000},
            "peers": [{"mid_hex": "bobmid", "wallet_address": "bcrt1qbob"}],
        },
        stop_predicate="bitcoin_confirmed_sent_sats(min_sats=20000)",
        stop_predicate_value=False,
        scenario_name="regtest_transfer",
        agent_name="alice",
    )

    assert out["next_action_guidance"]["phase"] == "confirm_payment"
    assert out["next_action_guidance"]["tool_call"] == {
        "name": "btc_mine_blocks",
        "arguments": {"num_blocks": 1},
    }


def test_regtest_guidance_tells_bob_to_wait_once_admitted() -> None:
    out = _snapshot_for_prompt(
        {
            "community": {"my_membership_status": "admitted"},
            "wallet": {"confirmed_received_sats": 10_000},
            "peers": [{"mid_hex": "alicemid", "wallet_address": "bcrt1qalice"}],
        },
        stop_predicate="wallet_received_sats(min_sats=20000)",
        stop_predicate_value=False,
        scenario_name="regtest_transfer",
        agent_name="bob",
    )

    guidance = out["next_action_guidance"]
    assert guidance["phase"] == "awaiting_alice_payment"
    assert guidance["tool_call"] is None
    assert "community_join_via_peer" in guidance["forbidden"]


def test_mock_regtest_guidance_tells_bob_to_join_once() -> None:
    out = _snapshot_for_prompt(
        {
            "network": {"admission": {"min_sats": 10_000}},
            "community": {"my_membership_status": "outsider", "member_count": 1},
            "peers": [{"mid_hex": "alicemid", "wallet_address": "bcrt1qalice"}],
        },
        stop_predicate="community_member_count_gte_N(n=2)",
        stop_predicate_value=False,
        scenario_name="mock_regtest_wallet_share",
        agent_name="bob",
    )

    guidance = out["next_action_guidance"]
    assert guidance["phase"] == "join_community"
    assert guidance["tool_call"] == {
        "name": "community_join_via_peer",
        "arguments": {"gatekeeper_mid": "alicemid", "amount_sats": 10_000},
    }
    assert "overlay_invoke" in guidance["forbidden"]


def test_mock_regtest_guidance_tells_alice_to_wallet_send_after_admission() -> None:
    out = _snapshot_for_prompt(
        {
            "community": {"member_count": 2},
            "peers": [{"mid_hex": "bobmid", "wallet_address": "bcrt1qbob"}],
        },
        stop_predicate="bitcoin_sent_sats(min_sats=20000)",
        stop_predicate_value=False,
        scenario_name="mock_regtest_wallet_share",
        agent_name="alice",
    )

    guidance = out["next_action_guidance"]
    assert guidance["phase"] == "send_payment"
    assert guidance["tool_call"] == {
        "name": "wallet_send",
        "arguments": {"to_address": "bcrt1qbob", "sats": 20_000},
    }
    assert "agent_inject_manifest" in guidance["forbidden"]


def test_mock_regtest_guidance_accepts_meta_only_peer_wallet() -> None:
    out = _snapshot_for_prompt(
        {
            "community": {"member_count": 2},
            "peers": [{
                "mid_hex": "bobmid",
                "address": None,
                "wallet_address": "bcrt1qmetabob",
                "known_overlays": [],
            }],
        },
        stop_predicate="bitcoin_sent_sats(min_sats=20000)",
        stop_predicate_value=False,
        scenario_name="mock_regtest_wallet_share",
        agent_name="alice",
    )

    assert out["next_action_guidance"]["tool_call"] == {
        "name": "wallet_send",
        "arguments": {"to_address": "bcrt1qmetabob", "sats": 20_000},
    }
