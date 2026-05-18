"""Parse + validate an agent mission descriptor (`mission.md`).

The mission is the single operator-supplied input the watchdog feeds
the LLM each turn. Schema is specified in ``deploy/mission_schema.md``.
The parser deliberately refuses recipes — backtick-quoted tool names
and ≥3-step lists under ``# Intent`` raise ``MissionParseError`` — so
the agent has to reason from its world (the state snapshot + manifest)
rather than execute a script the operator embedded.

This module imports only the standard library and ``deploy.stop_predicates``
to keep parse-time light; it does **not** import ``agent.tools``
(the tool-name list is hardcoded here so a missing dependency never
silently weakens the recipe filter).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from deploy import stop_predicates


REQUIRED_SECTIONS = ("Identity", "Intent", "Budget", "Stop")
ALLOWED_ROLES = ("seedbox", "seeker", "general")

# Hardcoded tool-name allowlist. Kept in sync with agent/tools.py:build_tools.
# If a tool name ever appears in `mission.md` body, the parser rejects it.
TOOL_NAMES: frozenset[str] = frozenset({
    "peers_list", "peer_add",
    "wallet_address", "wallet_balance", "wallet_send",
    "community_donate_and_join", "community_treasury_balance",
    "community_member_count", "community_log_list_recent",
    "community_join_via_peer",
    "seedbox_purchase_propose", "seedbox_provisioned",
    "overlays_list", "overlay_describe", "overlay_fetch_and_load",
    "overlay_publish", "overlay_invoke",
    "agent_inject_manifest",
    "torrent_seed", "torrent_fetch", "torrent_stats",
})

# Heuristic: a list under # Intent with this many entries or more is a recipe.
MAX_INTENT_LIST_ENTRIES = 2


class MissionParseError(Exception):
    """Raised when a mission descriptor fails schema validation."""


@dataclass(frozen=True)
class Budget:
    max_sats_outbound: int
    max_total_turns: int


@dataclass(frozen=True)
class Mission:
    name: str
    role: str
    intent_text: str
    budget: Budget
    stop_predicate: str
    raw_md: str


# ---------------------------------------------------------------------------
# Section splitter — same convention as protocol.compiler._split_top_sections
# ---------------------------------------------------------------------------

def _split_top_sections(text: str) -> tuple[dict[str, str], list[str]]:
    """Return (sections-by-name, ordered-list-of-section-names)."""
    sections: dict[str, str] = {}
    order: list[str] = []
    current: str | None = None
    body: list[str] = []
    for line in text.split("\n"):
        if line.startswith("# ") and not line.startswith("## "):
            if current is not None:
                sections[current] = "\n".join(body)
            current = line[2:].strip()
            body = []
            order.append(current)
        else:
            body.append(line)
    if current is not None:
        sections[current] = "\n".join(body)
    return sections, order


def _check_required_sections(order: list[str], sections: dict[str, str]) -> None:
    relevant = [s for s in order if s in REQUIRED_SECTIONS]
    if relevant != list(REQUIRED_SECTIONS):
        missing = [s for s in REQUIRED_SECTIONS if s not in sections]
        if missing:
            raise MissionParseError(f"missing required sections: {missing}")
        raise MissionParseError(
            f"required sections must appear in order {list(REQUIRED_SECTIONS)}; "
            f"got {relevant}"
        )


# ---------------------------------------------------------------------------
# Per-section validation
# ---------------------------------------------------------------------------

_KV_RE = re.compile(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$")
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_BACKTICK_RE = re.compile(r"`([^`]+)`")
_NUMBERED_STEP_RE = re.compile(r"^\s*\d+\.\s+\S")
_BULLETED_STEP_RE = re.compile(r"^\s*[-*]\s+\S")


def _parse_kv_list(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in body.split("\n"):
        m = _KV_RE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _parse_identity(body: str) -> tuple[str, str]:
    kv = _parse_kv_list(body)
    for required in ("name", "role"):
        if required not in kv:
            raise MissionParseError(f"# Identity missing key: {required!r}")
    name = kv["name"]
    if not _NAME_RE.match(name):
        raise MissionParseError(f"# Identity name not snake_case: {name!r}")
    role = kv["role"]
    if role not in ALLOWED_ROLES:
        raise MissionParseError(
            f"# Identity role must be one of {ALLOWED_ROLES}; got {role!r}"
        )
    return name, role


def _check_intent_has_no_recipe(body: str) -> None:
    """Reject backtick-quoted tool names + step-shaped lists.

    Implements the operator-facing rule from mission_schema.md: the
    intent should describe *what* the agent wants, not *how*.
    """
    for match in _BACKTICK_RE.finditer(body):
        token = match.group(1).strip()
        if token in TOOL_NAMES:
            raise MissionParseError(
                f"# Intent must not name a tool ({token!r} found in backticks); "
                "describe what you want, not which tool to call."
            )

    step_lines = 0
    for line in body.split("\n"):
        if _NUMBERED_STEP_RE.match(line) or _BULLETED_STEP_RE.match(line):
            step_lines += 1
    if step_lines > MAX_INTENT_LIST_ENTRIES:
        raise MissionParseError(
            f"# Intent must not contain a step-by-step list "
            f"({step_lines} bullet/numbered entries; threshold "
            f"{MAX_INTENT_LIST_ENTRIES}). Rewrite as prose."
        )


def _parse_budget(body: str) -> Budget:
    kv = _parse_kv_list(body)
    for required in ("max_sats_outbound", "max_total_turns"):
        if required not in kv:
            raise MissionParseError(f"# Budget missing key: {required!r}")
    try:
        sats = int(kv["max_sats_outbound"])
        turns = int(kv["max_total_turns"])
    except ValueError as exc:
        raise MissionParseError(
            f"# Budget values must be integers: {exc}"
        ) from exc
    if sats < 0:
        raise MissionParseError(
            f"# Budget max_sats_outbound must be >= 0; got {sats}"
        )
    if turns < 1:
        raise MissionParseError(
            f"# Budget max_total_turns must be >= 1; got {turns}"
        )
    return Budget(max_sats_outbound=sats, max_total_turns=turns)


def _parse_stop(body: str) -> str:
    kv = _parse_kv_list(body)
    if "predicate" not in kv:
        raise MissionParseError("# Stop missing key: 'predicate'")
    predicate = kv["predicate"]
    try:
        stop_predicates.resolve(predicate)
    except stop_predicates.UnknownPredicate as exc:
        raise MissionParseError(f"# Stop predicate {predicate!r}: {exc}") from exc
    return predicate


# ---------------------------------------------------------------------------
# Top-level entry
# ---------------------------------------------------------------------------

def parse_mission(text: str) -> Mission:
    """Parse + validate a ``mission.md``. Raise ``MissionParseError`` on any deviation."""
    if not isinstance(text, str):
        raise MissionParseError(f"mission must be str; got {type(text).__name__}")

    sections, order = _split_top_sections(text)
    _check_required_sections(order, sections)

    name, role = _parse_identity(sections["Identity"])
    intent_text = sections["Intent"].strip()
    if not intent_text:
        raise MissionParseError("# Intent must not be empty")
    _check_intent_has_no_recipe(intent_text)
    budget = _parse_budget(sections["Budget"])
    stop_predicate = _parse_stop(sections["Stop"])

    return Mission(
        name=name,
        role=role,
        intent_text=intent_text,
        budget=budget,
        stop_predicate=stop_predicate,
        raw_md=text,
    )
