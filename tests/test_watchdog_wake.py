"""``deploy.watchdog._wait_for_next_turn`` — the wake-watching sleep loop.

Pins the four behaviors the optimization promises:

  * **No signal, no floor concern:** the loop sleeps until ``tick_deadline``
    and returns ``"tick"`` — matches the prior unconditional ``asyncio.sleep``.
  * **Signal arrives BEFORE the floor elapses:** the loop honors the floor
    first; the signal is picked up only once ``MIN_FLOOR_S`` has passed.
    This is the protection against an LLM hot-loop.
  * **Signal arrives AFTER the floor elapses:** the loop wakes within one
    polling interval and returns ``"signal"``.
  * **Signal never arrives:** the loop returns ``"tick"`` at ``tick_deadline``.

All asyncio.sleep is patched so the tests run instantly (no real wall time).
"""

from __future__ import annotations

import asyncio
from typing import Iterator

import pytest

from deploy import watchdog


@pytest.fixture
def fake_clock(monkeypatch):
    """Replace ``time.monotonic`` with a manually-advanced clock and convert
    ``asyncio.sleep`` into a clock advance (no real wall time).

    Tests can ``advance(seconds)`` directly or let the loop sleep itself
    forward by awaiting the patched ``asyncio.sleep`` — both add to the same
    counter so ``time.monotonic()`` stays consistent."""
    now = [0.0]

    def monotonic():
        return now[0]

    async def fast_sleep(seconds):
        now[0] += max(0.0, seconds)

    monkeypatch.setattr(watchdog.time, "monotonic", monotonic)
    monkeypatch.setattr(watchdog.asyncio, "sleep", fast_sleep)

    def advance(seconds: float):
        now[0] += seconds

    return advance, now


def _drain(coro):
    """Run an async coroutine on a fresh event loop, returning its result."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture
def stub_self_dir(monkeypatch, tmp_path):
    """``_wait_for_next_turn`` reads from ``self_state_dir()`` + ``read_signal_mtime``.
    Stub both so a test can stage a "signal arrives at time T" scenario."""
    monkeypatch.setattr(watchdog, "self_state_dir", lambda: tmp_path)
    return tmp_path


def test_no_signal_returns_tick_at_deadline(fake_clock, stub_self_dir, monkeypatch):
    """The unsurprising baseline: nothing pokes the signal file -> the loop
    sleeps until ``tick_deadline`` and returns ``"tick"``."""
    monkeypatch.setattr(watchdog, "read_signal_mtime", lambda _d: 0.0)
    result = _drain(watchdog._wait_for_next_turn(
        tick_deadline=240.0, turn_end=0.0, min_floor_s=60.0,
        baseline_mtime=0.0, poll_s=2.0,
    ))
    _, now = fake_clock
    assert result == "tick"
    assert now[0] >= 240.0


def test_signal_before_floor_is_ignored_until_floor_elapses(fake_clock, stub_self_dir, monkeypatch):
    """The hot-loop protection: a signal that arrives during the first
    ``min_floor_s`` seconds must NOT wake the loop. The loop honors the
    signal only once the floor has passed — within one poll interval."""
    advance, now = fake_clock
    # Signal mtime jumps from 0 -> 100 at clock-time 10s, well before the
    # 60s floor. The loop should keep sleeping until at least t=60.
    def mtime(_dir):
        return 100.0 if now[0] >= 10.0 else 0.0

    monkeypatch.setattr(watchdog, "read_signal_mtime", mtime)
    result = _drain(watchdog._wait_for_next_turn(
        tick_deadline=240.0, turn_end=0.0, min_floor_s=60.0,
        baseline_mtime=0.0, poll_s=2.0,
    ))
    assert result == "signal"
    # Wake AFTER the floor elapsed, not at t=10 when the signal arrived.
    assert now[0] >= 60.0
    # And well before the deadline.
    assert now[0] < 240.0


def test_signal_after_floor_wakes_within_one_poll(fake_clock, stub_self_dir, monkeypatch):
    """The cross-agent speedup: floor has already elapsed, signal arrives
    at t=80; loop wakes within ``poll_s`` (2s) of the signal."""
    advance, now = fake_clock
    def mtime(_dir):
        return 100.0 if now[0] >= 80.0 else 0.0

    monkeypatch.setattr(watchdog, "read_signal_mtime", mtime)
    result = _drain(watchdog._wait_for_next_turn(
        tick_deadline=240.0, turn_end=0.0, min_floor_s=60.0,
        baseline_mtime=0.0, poll_s=2.0,
    ))
    assert result == "signal"
    assert 80.0 <= now[0] <= 82.0   # one poll interval at most


def test_no_self_state_dir_falls_back_to_tick(fake_clock, monkeypatch):
    """When ``self_state_dir()`` returns ``None`` (env-unset, ad-hoc dev run),
    the loop ignores the signal mechanism entirely and just sleeps to the
    deadline. Matches the pre-fix behavior; protects unit tests."""
    monkeypatch.setattr(watchdog, "self_state_dir", lambda: None)
    monkeypatch.setattr(watchdog, "read_signal_mtime", lambda _d: 999.0)
    result = _drain(watchdog._wait_for_next_turn(
        tick_deadline=240.0, turn_end=0.0, min_floor_s=60.0,
        baseline_mtime=0.0, poll_s=2.0,
    ))
    _, now = fake_clock
    assert result == "tick"
    assert now[0] >= 240.0


def test_self_wake_via_pre_turn_baseline(fake_clock, stub_self_dir, monkeypatch):
    """The deployed bug shape (2026-05-30 12:27): a tool finishing in this
    turn touched THIS agent's own .wake_signal (e.g. content_search_and_fetch
    advancing fetch->author). The watchdog must wake on that — baseline_mtime
    is captured BEFORE the turn ran, and the post-turn mtime now exceeds it.
    Pre-fix this test would have failed: the baseline was captured AFTER the
    turn (after the self-touch), so subsequent reads compared equal and the
    wake never fired."""
    advance, now = fake_clock
    # Simulate the deployed timeline: pre-turn mtime was 0 (no signal yet),
    # the turn ran and touched the file (mtime jumped to 50 at t=5), then
    # the watchdog enters _wait_for_next_turn with baseline=0 (pre-turn).
    monkeypatch.setattr(watchdog, "read_signal_mtime", lambda _d: 50.0)
    result = _drain(watchdog._wait_for_next_turn(
        tick_deadline=240.0,
        turn_end=5.0,           # turn took 5s
        min_floor_s=60.0,
        baseline_mtime=0.0,     # captured BEFORE the turn — the fix
        poll_s=2.0,
    ))
    assert result == "signal"
    # Wake after the floor elapses (60s past turn_end, so >= 65s wall),
    # not at the deadline.
    assert 65.0 <= now[0] < 240.0


def test_self_wake_pre_fix_regression(fake_clock, stub_self_dir, monkeypatch):
    """Inverse of the previous test — pin that we DON'T regress by passing
    a post-turn baseline. The pre-fix bug: baseline captured AFTER the turn
    means a self-touch from the turn IS in the baseline, so subsequent reads
    compare equal, and we sleep to the deadline."""
    advance, now = fake_clock
    monkeypatch.setattr(watchdog, "read_signal_mtime", lambda _d: 50.0)
    result = _drain(watchdog._wait_for_next_turn(
        tick_deadline=240.0,
        turn_end=5.0,
        min_floor_s=60.0,
        baseline_mtime=50.0,    # POST-turn (pre-fix shape)
        poll_s=2.0,
    ))
    assert result == "tick"      # no wake fires; sleep to deadline.


def test_deadline_already_passed_returns_tick_immediately(fake_clock, stub_self_dir, monkeypatch):
    """If a turn ran long (close to ``interval_s``), the next sleep should
    return immediately — never block. Negative ``tick_remaining`` was the
    pre-fix invariant; preserve it here."""
    monkeypatch.setattr(watchdog, "read_signal_mtime", lambda _d: 0.0)
    result = _drain(watchdog._wait_for_next_turn(
        tick_deadline=0.0, turn_end=0.0, min_floor_s=60.0,
        baseline_mtime=0.0, poll_s=2.0,
    ))
    assert result == "tick"
