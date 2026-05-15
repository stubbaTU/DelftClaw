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


_AVAILABLE_TOOLS = (
    "peers_list, peer_add, wallet_address, wallet_balance, wallet_send, "
    "seedbox_donate_and_join, overlays_list, overlay_describe, "
    "overlay_fetch_and_load, overlay_invoke, overlay_publish, "
    "agent_inject_manifest, network_join, torrent_seed, torrent_fetch, "
    "torrent_stats"
)


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
    mission_text: str,
    snapshot: dict[str, Any],
    history: TurnHistory,
) -> str:
    """Assemble the LLM-facing prompt for one watchdog tick.

    The order is fixed: ``mission`` first (intent + budget + stop), then
    the current STATE block (JSON, human-readable indent), then a flat
    OBSERVED FACTS section derived from the snapshot, then the RECENT
    TURNS tail. Determinism here is load-bearing — JSONL replay assumes
    the same builder produces the same bytes from the same inputs.

    The mission is the *only* operator-supplied prose the LLM sees;
    every other prompt input is either machine-generated (state snapshot,
    history tail, observed facts) or content-hashed (the network
    manifest, which lives inside the snapshot).
    """
    sections: list[str] = ["MISSION:", mission_text.rstrip(), ""]
    sections.append("CURRENT STATE:")
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
    sections.append("")
    sections.append("INSTRUCTIONS:")
    sections.append("- Respond with exactly one MCP tool call. Do not respond with chat prose.")
    sections.append("- The watchdog evaluates the stop predicate against real state — never claim the mission is complete yourself.")
    sections.append("- If you are unsure what to do next, call ``peers_list`` or ``wallet_balance`` to refresh state.")
    sections.append(f"- Available tools: {_AVAILABLE_TOOLS}.")
    return "\n".join(sections)


def turn_cap_reached(turn_n: int, max_total_turns: int) -> bool:
    """``True`` when ``turn_n`` (1-indexed) has hit or exceeded the cap."""
    return turn_n >= max_total_turns


def wall_clock_exceeded(elapsed_s: float, max_wall_clock_s: int) -> bool:
    """``True`` when the scenario clock has exceeded its hard timeout."""
    return elapsed_s >= max_wall_clock_s
