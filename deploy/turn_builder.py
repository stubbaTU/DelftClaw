"""Pure-function helpers for the watchdog's turn-prompt construction.

Kept isolated from the watchdog driver so the deterministic part of each
turn (what the LLM sees) is testable without IPv8 / subprocess / time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class TurnRecord:
    """One past turn, retained in the watchdog's history."""

    turn_n: int
    prompt: str
    response_text: str
    stop_predicate_value: bool

    def summary(self) -> str:
        """Compact one-paragraph summary used in subsequent turn prompts."""
        body = self.response_text.strip()
        if len(body) > 600:
            body = body[:600] + "..."
        return f"[turn {self.turn_n}] {body}"


@dataclass
class TurnHistory:
    """Bounded ring buffer of the last ``max_tail`` turns."""

    max_tail: int = 3
    _records: list[TurnRecord] = field(default_factory=list)

    def append(self, record: TurnRecord) -> None:
        self._records.append(record)
        if len(self._records) > self.max_tail:
            del self._records[: len(self._records) - self.max_tail]

    def tail(self) -> list[TurnRecord]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)


def build_turn_prompt(
    mission_text: str,
    snapshot: dict[str, Any],
    history: TurnHistory,
) -> str:
    """Assemble the LLM-facing prompt for one watchdog tick.

    The order is fixed: ``mission`` first (intent + budget + stop), then
    the current STATE block (JSON, human-readable indent), then the
    RECENT TURNS tail. Determinism here is load-bearing - JSONL replay
    assumes the same builder produces the same bytes from the same
    inputs.

    The mission is the *only* operator-supplied prose the LLM sees;
    every other prompt input is either machine-generated (state snapshot,
    history tail) or content-hashed (the network manifest, which lives
    inside the snapshot).

    The leading ``ROLE`` block is the only framing the agent gets that
    isn't operator-supplied. It exists because LLMs (especially smaller
    chat-tuned ones) default to addressing a human user - they introduce
    themselves, ask "how can I help?", or describe what they would do
    rather than act. The framing tells the model up front that no human
    is reading and the only acceptable output is a tool call or an
    explicit empty wait when another agent must act.
    """
    sections: list[str] = [
        "HARD CONSTRAINT - READ THIS FIRST:",
        "EXACTLY ONE tool call this turn at most. Then STOP.",
        "  * The MCP server enforces this. The 2nd, 3rd, ... tool calls",
        "    you make this turn will return tool_budget_exhausted and",
        "    will NOT be executed.",
        "  * After your one tool call returns, emit an empty assistant",
        "    message and end the turn immediately. Do NOT plan further",
        "    actions. Do NOT call another tool 'just in case'. Do NOT",
        "    explain what you would do next.",
        "  * The watchdog wakes you again with a fresh state snapshot",
        "    on the next tick - pick the next action then, not now.",
        "  * Every extra tool call costs provider rate-limit budget",
        "    every other agent in this scenario also needs.",
        "",
        "ROLE:",
        "You are an autonomous agent operating without human supervision.",
        "No user is reading these messages. Do not greet, introduce",
        "yourself, ask clarifying questions, or describe what you would",
        "do.",
        "",
        "PROGRESS DISCIPLINE:",
        "The CURRENT STATE block below already contains everything you",
        "can observe this turn: your wallet, the network/admission",
        "policy, the community treasury + your membership status, your",
        "peers, the loaded protocol overlays, and your torrents. It was",
        "collected for you. Calling a read-only tool to fetch any of",
        "that again is NOT progress and wastes your only action.",
        "",
        "Your turn must MOVE THE MISSION FORWARD. If your stop",
        "predicate is not yet satisfied and you can personally close the",
        "next gap, your one tool call must CHANGE STATE - not observe",
        "it. Compare CURRENT STATE to your mission's end goal, find the",
        "single biggest gap, and take the one action that closes it.",
        "Re-reading state you already have is the one thing that",
        "guarantees no progress.",
        "",
        "If CURRENT STATE already satisfies your mission's stop",
        "condition, or if your mission is waiting for another agent's",
        "state-changing action and you have no useful state change left",
        "to make, do nothing: emit an empty assistant message with NO",
        "tool call and end. The harness tears you down on the next tick",
        "once your stop_predicate is satisfied. Do NOT call a read tool",
        "as a stand-in for doing nothing.",
        "",
        "When CURRENT STATE contains stop_predicate.satisfied, that value",
        "is authoritative. It has already been evaluated by the watchdog",
        "against scenario baselines. Do NOT infer stop completion from",
        "raw absolute counters such as wallet totals.",
        "",
        "MISSION:",
        mission_text.rstrip(),
        "",
    ]
    sections.append("CURRENT STATE:")
    sections.append("```json")
    sections.append(json.dumps(snapshot, indent=2, sort_keys=True))
    sections.append("```")
    sections.append("")
    if len(history):
        sections.append("RECENT TURNS:")
        for record in history.tail():
            sections.append(record.summary())
    else:
        sections.append("RECENT TURNS: (none yet - this is the first turn)")
    sections.append("")
    sections.append(
        "Reminder: make at most ONE state-CHANGING tool call this turn, "
        "then STOP. If you are waiting for another agent and have no "
        "useful state change left, emit an empty assistant message with "
        "NO tool call. Re-reading state you were already given is not "
        "progress and is not an acceptable action. The MCP server "
        "rejects any subsequent tool call in this session with "
        "tool_budget_exhausted."
    )
    return "\n".join(sections)


def turn_cap_reached(turn_n: int, max_total_turns: int) -> bool:
    """``True`` when ``turn_n`` (1-indexed) has hit or exceeded the cap."""
    return turn_n >= max_total_turns


def wall_clock_exceeded(elapsed_s: float, max_wall_clock_s: int) -> bool:
    """``True`` when the scenario clock has exceeded its hard timeout."""
    return elapsed_s >= max_wall_clock_s
