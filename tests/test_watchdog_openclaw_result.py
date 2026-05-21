from __future__ import annotations

from deploy.watchdog import _classify_openclaw_turn


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
