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


def test_summary_truncates_long_responses():
    r = TurnRecord(turn_n=7, prompt="p", response_text="x" * 1000,
                   stop_predicate_value=False)
    s = r.summary()
    assert s.startswith("[turn 7]")
    assert s.endswith("...")
    assert len(s) < 700


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------

def test_prompt_is_deterministic_for_same_inputs():
    mission = "MISSION:\n- name: tester\n- role: general\n\nDo the test."
    snapshot = {"peers": [], "wallet": {"balance_sats": 0}}
    h = TurnHistory()
    a = build_turn_prompt(mission, snapshot, h)
    b = build_turn_prompt(mission, snapshot, h)
    assert a == b


def test_prompt_orders_sections_correctly():
    out = build_turn_prompt(
        mission_text="MISSION-BLOCK",
        snapshot={"k": "v"},
        history=TurnHistory(),
    )
    mission_idx = out.index("MISSION-BLOCK")
    state_idx = out.index("CURRENT STATE:")
    recent_idx = out.index("RECENT TURNS")
    assert mission_idx < state_idx < recent_idx


def test_prompt_includes_serialised_snapshot_with_sorted_keys():
    out = build_turn_prompt(
        mission_text="m",
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
                        stop_predicate_value=False))
    out = build_turn_prompt("m", {}, h)
    assert "[turn 1]" in out
    assert "[turn 2]" in out
    assert "first turn happened" in out
    assert "second turn happened" in out


def test_prompt_says_none_yet_on_first_turn():
    out = build_turn_prompt("m", {}, TurnHistory())
    assert "RECENT TURNS: (none yet" in out


def test_prompt_orders_hard_constraint_role_then_mission():
    out = build_turn_prompt("MISSION-BODY", {}, TurnHistory())
    # Non-operator-supplied prose is only allowed above MISSION:. The
    # one-tool-per-turn HARD CONSTRAINT sits at the very top to maximise
    # the chance the LLM honours it; ROLE: framing is next; MISSION: is
    # the first operator-supplied content. The relative order is the
    # operator-trust boundary — anything above MISSION: must be code-
    # supplied, never user-supplied.
    lines = out.split("\n")
    assert "HARD CONSTRAINT — READ THIS FIRST:" in lines
    assert "ROLE:" in lines
    assert "MISSION:" in lines
    hard_idx = lines.index("HARD CONSTRAINT — READ THIS FIRST:")
    role_idx = lines.index("ROLE:")
    mission_idx = lines.index("MISSION:")
    assert hard_idx < role_idx < mission_idx
    assert hard_idx == 0  # nothing slips above the budget rule


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
