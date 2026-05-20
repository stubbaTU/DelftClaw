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

    The order is fixed: code-supplied hard constraints first, then
    ``mission`` (intent + budget + stop), then the current STATE block
    (JSON, human-readable indent), then the RECENT TURNS tail.
    Determinism here is load-bearing — JSONL replay assumes the same
    builder produces the same bytes from the same inputs.

    The mission is the *only* operator-supplied prose the LLM sees;
    every other prompt input is either machine-generated (state snapshot,
    history tail) or content-hashed (the network manifest, which lives
    inside the snapshot).
    The leading framing is the only prose the agent gets that isn't
    operator-supplied. It exists because small and mid-sized chat models
    otherwise tend to narrate, ask for confirmation, or spend turns on
    read-only observation loops instead of making one useful state change.
    """
    sections: list[str] = [
        "HARD CONSTRAINT — READ THIS FIRST:",
        "EXACTLY ONE tool call this turn. Then STOP.",
        "  * The MCP server enforces this. Further tool calls in this",
        "    turn can be rejected and will not move the scenario.",
        "  * After your one tool call returns, emit an empty assistant",
        "    message and end the turn immediately.",
        "  * The watchdog wakes you again with a fresh state snapshot",
        "    on the next tick — pick the next action then, not now.",
        "",
        "ROLE:",
        "You are an autonomous agent operating without human supervision.",
        "No user is reading these messages. Do not greet, introduce",
        "yourself, ask clarifying questions, or describe what you would do.",
        "",
        "PROGRESS DISCIPLINE:",
        "The CURRENT STATE block below already contains the state you can",
        "observe this turn: wallet, network/admission policy, community",
        "summary, peers, loaded protocol overlays, torrents, and security",
        "evidence when present. It was collected for you.",
        "",
        "Your turn must MOVE THE MISSION FORWARD. If your stop predicate",
        "is not yet satisfied, your one tool call must CHANGE STATE — not",
        "observe it. Compare CURRENT STATE to your mission's end goal,",
        "find the single biggest gap, and take the one action that closes",
        "it. Re-reading state you already have is NOT progress.",
        "",
        "If — and only if — CURRENT STATE already satisfies your mission's",
        "stop condition, do nothing: emit an empty assistant message with",
        "NO tool call and end. Do not call a read tool as a stand-in for",
        "doing nothing.",
        "",
        "MISSION:",
        mission_text.rstrip(),
        "",
    ]
    sections.append("TURN CONTRACT:")
    sections.append(
        "- Make at most one purposeful DelftClaw MCP tool call for this turn, "
        "then stop and summarize the result."
    )
    sections.append(
        "- Do not try to finish the whole mission in one subprocess run; the "
        "watchdog will call you again with fresh state."
    )
    sections.append(
        "- If no safe tool call is possible from the current state, return a "
        "short explanation instead of waiting."
    )
    sections.append("")
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
        sections.append("RECENT TURNS: (none yet — this is the first turn)")
    sections.append("")
    sections.append(
        "Now perform one bounded action for this turn. It should change state "
        "unless the current state already satisfies your mission."
    )
    return "\n".join(sections)


def turn_cap_reached(turn_n: int, max_total_turns: int) -> bool:
    """``True`` when ``turn_n`` (1-indexed) has hit or exceeded the cap."""
    return turn_n >= max_total_turns


def wall_clock_exceeded(elapsed_s: float, max_wall_clock_s: int) -> bool:
    """``True`` when the scenario clock has exceeded its hard timeout."""
    return elapsed_s >= max_wall_clock_s
