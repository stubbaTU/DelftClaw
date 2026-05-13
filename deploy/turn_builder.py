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
    persona: str,
    goal: str,
    snapshot: dict[str, Any],
    history: TurnHistory,
) -> str:
    """Assemble the LLM-facing prompt for one watchdog tick.

    The order is fixed: ``persona`` first (system-prompt style), then the
    goal (specific to the scenario), then the current STATE block (JSON,
    human-readable indent), then the RECENT TURNS tail. Determinism here
    is load-bearing — JSONL replay assumes the same builder produces the
    same bytes from the same inputs.
    """
    sections: list[str] = [persona.rstrip(), "", goal.rstrip(), ""]
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
    sections.append("Now decide what tool to call.")
    return "\n".join(sections)


def turn_cap_reached(turn_n: int, max_total_turns: int) -> bool:
    """``True`` when ``turn_n`` (1-indexed) has hit or exceeded the cap."""
    return turn_n >= max_total_turns


def wall_clock_exceeded(elapsed_s: float, max_wall_clock_s: int) -> bool:
    """``True`` when the scenario clock has exceeded its hard timeout."""
    return elapsed_s >= max_wall_clock_s
