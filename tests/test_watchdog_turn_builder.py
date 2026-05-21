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
    assert "HARD CONSTRAINT - READ THIS FIRST:" in lines
    assert "ROLE:" in lines
    assert "MISSION:" in lines
    hard_idx = lines.index("HARD CONSTRAINT - READ THIS FIRST:")
    role_idx = lines.index("ROLE:")
    mission_idx = lines.index("MISSION:")
    assert hard_idx < role_idx < mission_idx
    assert hard_idx == 0  # nothing slips above the budget rule


def test_prompt_progress_discipline_does_not_teach_read_loop():
    """Regression: the framing must NOT instruct the LLM to call a
    read-only tool as a no-op, and must tell it re-reading state is
    not progress.

    Why this exists: an earlier turn prompt said "if the state already
    satisfies the mission, call ONE cheap no-op (e.g. wallet_balance)
    and end." Once the per-session budget exempted read tools, that
    line trained Haiku to spend every post-join turn on 6 free
    read-only calls and never act — seek_cc reached member_count=4 but
    never did SEARCH / torrent_fetch / seedbox_purchase_propose (concept
    steps 4,5,7). The fix replaced it with: snapshot is already in the
    prompt, re-reading is not progress, the one action must change
    state, and the only no-op is an EMPTY assistant message.
    """
    out = build_turn_prompt("# Intent\nGet the file.", {"torrents": []}, TurnHistory())
    lines = out.split("\n")

    # The block exists and sits in the code-supplied region (above MISSION).
    assert "PROGRESS DISCIPLINE:" in lines
    assert lines.index("ROLE:") < lines.index("PROGRESS DISCIPLINE:") < lines.index("MISSION:")

    # It must NOT name a read-only tool anywhere as a suggested action /
    # no-op. These are the budget-free observe tools; the old prompt
    # named wallet_balance explicitly.
    for read_tool in (
        "wallet_balance", "wallet_address", "peers_list",
        "community_treasury_balance", "overlays_list", "torrent_stats",
    ):
        assert read_tool not in out, (
            f"turn prompt names read-only tool {read_tool!r} — this "
            f"re-teaches the post-join read-loop"
        )

    # It must explicitly say re-reading state is not progress, and the
    # valid no-op is an empty message (no tool call). Collapse whitespace
    # so line-wrapping in the prompt body doesn't break the substring.
    flat = " ".join(out.split())
    assert "NOT progress" in flat
    assert "empty assistant message with NO tool call" in flat
    assert "waiting for another agent" in flat


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
