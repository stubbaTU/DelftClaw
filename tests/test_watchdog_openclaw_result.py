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
