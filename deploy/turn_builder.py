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
        """Compact summary used in subsequent turn prompts.

        Deliberately drops ``response_text``: when the LLM hallucinates
        success in turn N (claiming "mission complete" with invented
        balances / magnet hashes), echoing that prose into turn N+1's
        RECENT TURNS section caused the agent to double down on the
        hallucination. The watchdog's authoritative signal is the
        stop-predicate value derived from the real snapshot, not the
        agent's own narration. (Observed 2026-05-15 with Haiku.)
        """
        return f"[turn {self.turn_n}] stop_predicate={self.stop_predicate_value}"


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


def _observed_facts(snapshot: dict[str, Any]) -> list[str]:
    """Derive a small set of authoritative facts from the snapshot.

    Counters the failure mode where the LLM hallucinates mission progress
    based on the mission text alone (e.g. claims a torrent is at
    ``progress=1`` when ``torrents`` is in fact empty). Each line is a
    flat assertion read directly from ``snapshot`` — facts the model
    cannot contradict without lying about the JSON it was just shown.
    """
    facts: list[str] = []
    wallet = snapshot.get("wallet") or {}
    balance = wallet.get("balance_sats")
    facts.append(f"- wallet_balance_sats: {balance}")

    admission = (snapshot.get("network") or {}).get("admission") or {}
    min_sats = admission.get("min_sats")
    if isinstance(balance, int) and isinstance(min_sats, int):
        if balance >= min_sats:
            facts.append(f"- wallet meets admission floor ({min_sats}); admission may still need an on-chain donation")
        else:
            facts.append(f"- wallet < admission floor ({min_sats}) — you are NOT yet admitted to the community")

    overlays = snapshot.get("overlays") or []
    if overlays:
        facts.append(f"- overlays_loaded: {len(overlays)}")
    else:
        facts.append("- overlays_loaded: 0 — you have NOT joined any community overlay yet")

    torrents = snapshot.get("torrents") or []
    if not torrents:
        facts.append("- torrents: 0 — you have NOT fetched any file; torrent_progress is 0")
    else:
        max_prog = max((t.get("progress", 0) for t in torrents), default=0)
        facts.append(f"- torrents: {len(torrents)} loaded; max progress = {max_prog}")

    peers = snapshot.get("peers") or []
    facts.append(f"- peers_known: {len(peers)}")
    return facts


def build_turn_prompt(
    snapshot: dict[str, Any],
    history: TurnHistory,
) -> str:
    """Assemble the per-tick user-message the LLM sees.

    Path A refactor (2026-05-17): identity (SOUL.md), operating loop +
    tool catalog (AGENTS.md), and tick rhythm (HEARTBEAT.md) all moved
    into the openclaw workspace, where they are auto-injected into the
    *system* prompt on every ``openclaw agent`` call. This builder is
    now responsible only for the *deterministic state* the agent must
    react to this tick:

      1. CURRENT STATE  — the JSON snapshot (sorted keys for determinism).
      2. OBSERVED FACTS — flat assertions derived from the snapshot, the
         authoritative counter to LLM hallucination of mission progress.
      3. RECENT TURNS   — the bounded history tail (summaries only — see
         ``TurnRecord.summary`` for the no-response-echo rationale).

    Determinism here is load-bearing — JSONL replay assumes the same
    builder produces the same bytes from the same inputs.
    """
    sections: list[str] = ["CURRENT STATE:"]
    sections.append("```json")
    sections.append(json.dumps(snapshot, indent=2, sort_keys=True))
    sections.append("```")
    sections.append("")
    sections.append("OBSERVED FACTS (derived from CURRENT STATE — authoritative):")
    sections.extend(_observed_facts(snapshot))
    sections.append("")
    if len(history):
        sections.append("RECENT TURNS:")
        for record in history.tail():
            sections.append(record.summary())
    else:
        sections.append("RECENT TURNS: (none yet — this is the first turn)")
    return "\n".join(sections)


def turn_cap_reached(turn_n: int, max_total_turns: int) -> bool:
    """``True`` when ``turn_n`` (1-indexed) has hit or exceeded the cap."""
    return turn_n >= max_total_turns


def wall_clock_exceeded(elapsed_s: float, max_wall_clock_s: int) -> bool:
    """``True`` when the scenario clock has exceeded its hard timeout."""
    return elapsed_s >= max_wall_clock_s
