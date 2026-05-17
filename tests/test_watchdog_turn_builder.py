"""Pure-function tests for ``deploy.turn_builder``.

The watchdog's behaviour is large but its *deterministic core* is small:
how the prompt is assembled, how history is truncated, how caps fire.
These tests exercise only that core.
"""

from __future__ import annotations

import pytest

from deploy.turn_builder import (
    TurnHistory,
    TurnRecord,
    build_turn_prompt,
    turn_cap_reached,
    wall_clock_exceeded,
)


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

def test_history_tail_is_bounded():
    h = TurnHistory(max_tail=3)
    for i in range(1, 6):
        h.append(TurnRecord(turn_n=i, prompt=f"p{i}", response_text=f"r{i}",
                            stop_predicate_value=False))
    tail = h.tail()
    assert [r.turn_n for r in tail] == [3, 4, 5]


def test_history_empty_initially():
    h = TurnHistory()
    assert len(h) == 0
    assert h.tail() == []


def test_summary_drops_response_text():
    # The hallucination-feedback fix (2026-05-15): summary does NOT
    # echo the assistant's free-text reply back into the next turn's
    # RECENT TURNS, because the LLM treated its own past prose as
    # ground truth and doubled down on hallucinated success.
    r = TurnRecord(turn_n=7, prompt="p",
                   response_text="MISSION COMPLETE — torrent at 100%",
                   stop_predicate_value=False)
    s = r.summary()
    assert s.startswith("[turn 7]")
    assert "MISSION COMPLETE" not in s
    assert "stop_predicate=False" in s


def test_summary_reflects_stop_predicate_value():
    r_pending = TurnRecord(turn_n=3, prompt="p", response_text="anything",
                           stop_predicate_value=False)
    r_done = TurnRecord(turn_n=4, prompt="p", response_text="anything",
                        stop_predicate_value=True)
    assert "stop_predicate=False" in r_pending.summary()
    assert "stop_predicate=True" in r_done.summary()


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------

def test_prompt_is_deterministic_for_same_inputs():
    # Path A refactor (2026-05-17): MISSION + INSTRUCTIONS + tool catalog
    # have moved out of the per-turn prompt and into static openclaw
    # workspace files (SOUL.md/AGENTS.md/HEARTBEAT.md). ``build_turn_prompt``
    # no longer takes a mission argument.
    snapshot = {"peers": [], "wallet": {"balance_sats": 0}}
    h = TurnHistory()
    a = build_turn_prompt(snapshot, h)
    b = build_turn_prompt(snapshot, h)
    assert a == b


def test_prompt_orders_state_facts_recent():
    out = build_turn_prompt(
        snapshot={"k": "v"},
        history=TurnHistory(),
    )
    state_idx = out.index("CURRENT STATE:")
    facts_idx = out.index("OBSERVED FACTS")
    recent_idx = out.index("RECENT TURNS")
    assert state_idx < facts_idx < recent_idx
    # MISSION header is gone (moved to SOUL.md).
    assert "MISSION:" not in out


def test_prompt_omits_mission_block():
    out = build_turn_prompt(snapshot={"k": "v"}, history=TurnHistory())
    # The MISSION block has moved to SOUL.md (auto-injected by openclaw
    # into the system prompt). It must not leak back into the per-turn
    # user message — that defeats the whole point of the refactor.
    assert "MISSION:" not in out
    # Even a sentinel passed via snapshot keys must not synthesise a
    # MISSION header — there is no longer any code path that emits one.
    sentinel_out = build_turn_prompt(
        snapshot={"MISSION-BLOCK": "should-not-leak"},
        history=TurnHistory(),
    )
    # The key string can appear inside the JSON snapshot block, but the
    # literal "MISSION:" header must not.
    assert "MISSION:" not in sentinel_out


def test_prompt_omits_instructions_block():
    out = build_turn_prompt(snapshot={"k": "v"}, history=TurnHistory())
    # INSTRUCTIONS + the available-tools enumeration have moved to
    # AGENTS.md (system-prompt-injected).
    assert "INSTRUCTIONS:" not in out
    assert "Available tools:" not in out


def test_prompt_includes_serialised_snapshot_with_sorted_keys():
    out = build_turn_prompt(
        snapshot={"b": 2, "a": 1, "c": [3]},
        history=TurnHistory(),
    )
    # Keys are sorted in JSON output.
    block_start = out.index("```json")
    block_end = out.index("```", block_start + 1)
    json_block = out[block_start:block_end]
    assert json_block.index('"a"') < json_block.index('"b"') < json_block.index('"c"')


def test_prompt_lists_recent_turns_when_history_present():
    h = TurnHistory(max_tail=2)
    h.append(TurnRecord(turn_n=1, prompt="p", response_text="first turn happened",
                        stop_predicate_value=False))
    h.append(TurnRecord(turn_n=2, prompt="p", response_text="second turn happened",
                        stop_predicate_value=True))
    out = build_turn_prompt({}, h)
    assert "[turn 1]" in out
    assert "[turn 2]" in out
    # response_text is intentionally NOT echoed (hallucination-feedback fix).
    assert "first turn happened" not in out
    assert "second turn happened" not in out
    # stop_predicate value IS echoed.
    assert "stop_predicate=False" in out
    assert "stop_predicate=True" in out


def test_prompt_says_none_yet_on_first_turn():
    out = build_turn_prompt({}, TurnHistory())
    assert "RECENT TURNS: (none yet" in out


def test_prompt_ends_with_action_trigger():
    # 2026-05-17: without a per-tick imperative in the user message,
    # Haiku replied "NO_REPLY" and made no tool call — the AGENTS.md
    # instructions in the system prompt weren't strong enough. The
    # trigger line is the only verb the agent sees each tick.
    out = build_turn_prompt({"k": "v"}, TurnHistory())
    assert out.rstrip().endswith(
        "Pick the single best tool to call now to advance toward your goal."
    )


# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("turn_n,cap,expected", [
    (1, 50, False),
    (49, 50, False),
    (50, 50, True),
    (99, 50, True),
])
def test_turn_cap(turn_n: int, cap: int, expected: bool):
    assert turn_cap_reached(turn_n, cap) is expected


@pytest.mark.parametrize("elapsed,cap,expected", [
    (0.0, 1800, False),
    (1799.9, 1800, False),
    (1800.0, 1800, True),
    (3600.0, 1800, True),
])
def test_wall_clock_cap(elapsed: float, cap: int, expected: bool):
    assert wall_clock_exceeded(elapsed, cap) is expected
