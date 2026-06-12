"""Claude Code session-JSONL parser (plan 2026-06-11 §1.2 + §0.1).

``openclaw agent --json`` is opaque under the stream-json backend (§0.4): the
authoritative per-tool-call record is the Claude Code *session JSONL* at
``<home>/.claude/projects/<path-hash>/<sessionId>.jsonl``. The live runtime
parses it for the FENCE CHECK (any main-chain ``tool_use`` whose name is not
``mcp__harness__*`` means the lockdown leaked) and for the agent's ``final_text``.

The schema is the verbatim shape probed against real session files (§0.1):

* one JSON object per line; ``type`` is ``assistant`` / ``user`` / ``system``
  plus non-message bookkeeping types (``mode``, ``permission-mode``,
  ``file-history-snapshot``, ``attachment``, ``ai-title``, ``last-prompt``)
  which we skip rather than choke on;
* assistant tool calls: ``message.content[]`` block
  ``{"type":"tool_use","id":"toolu_…","name":<tool>,"input":{…}}`` (an optional
  ``caller`` key may be present -- never required);
* tool results: a ``user`` line carrying
  ``{"type":"tool_result","tool_use_id":<id>,"content":<str | list-of-blocks>}``
  with optional ``is_error``; ``content`` is sometimes a plain string and
  sometimes a list of typed blocks -- both are normalised to text;
* subagent traffic carries ``isSidechain: true`` and is EXCLUDED from the trace;
* the final agent answer is the LAST ``text`` block on a main-chain assistant
  line; pairing is ``tool_result.tool_use_id`` <-> ``tool_use.id``.

A line that fails ``json.loads`` RAISES: a truncated tail means the turn is
unreliable, so we fail loud rather than score a partial trace. Stdlib only --
this module must be importable WITHOUT fastmcp.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class JsonlToolCall:
    """One main-chain tool call reconstructed from the session JSONL.

    ``id`` pairs the ``tool_use`` block to its ``tool_result``; ``name`` is the
    raw tool name (MCP tools appear as ``mcp__<server>__<tool>``); ``input`` is
    the call's argument mapping; ``result_text`` is the normalised result text
    (``None`` until a matching result is seen); ``is_error`` mirrors the
    optional ``tool_result.is_error`` flag (``False`` when absent).
    """

    id: str
    name: str
    input: dict[str, Any]
    result_text: str | None = None
    is_error: bool = False


@dataclass
class SessionTrace:
    """Parsed main-chain trace: the tool calls (in order) + the final text."""

    tool_calls: list[JsonlToolCall] = field(default_factory=list)
    final_text: str | None = None


def _normalise_content(content: Any) -> str:
    """Reduce a ``tool_result.content`` (str OR list-of-blocks) to text (§0.1)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
                else:
                    parts.append(json.dumps(block))
            else:
                parts.append(str(block))
        return "".join(parts)
    return str(content)


def parse_session_jsonl(path: str | Path) -> SessionTrace:
    """Parse the session JSONL at ``path`` into a :class:`SessionTrace`.

    Skips bookkeeping (non-message) types and any ``isSidechain`` line, pairs
    results to uses by id (results may arrive out of order), normalises
    str-vs-list ``content`` to text, and tracks the last main-chain assistant
    ``text`` block as ``final_text``. RAISES on a line that is not valid JSON.
    """
    path = Path(path)
    calls: list[JsonlToolCall] = []
    by_id: dict[str, JsonlToolCall] = {}
    final_text: str | None = None

    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        if not line.strip():
            continue
        # A malformed line is fatal (§0.1): a truncated tail makes the turn
        # unreliable -- fail loud rather than score a partial trace.
        record = json.loads(line)

        if not isinstance(record, dict):
            continue
        # Subagent traffic is not part of the main-chain trace (§0.1).
        if record.get("isSidechain"):
            continue

        rtype = record.get("type")
        if rtype not in ("assistant", "user"):
            # Bookkeeping types (mode, permission-mode, file-history-snapshot,
            # attachment, ai-title, last-prompt, system, ...) carry no trace.
            continue

        message = record.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue

        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if rtype == "assistant" and btype == "tool_use":
                call = JsonlToolCall(
                    id=block.get("id"),
                    name=block.get("name"),
                    input=block.get("input", {}),
                )
                calls.append(call)
                by_id[call.id] = call
            elif rtype == "assistant" and btype == "text":
                # Final answer = the LAST main-chain text block seen (§0.1).
                final_text = block.get("text")
            elif rtype == "user" and btype == "tool_result":
                call = by_id.get(block.get("tool_use_id"))
                if call is not None:
                    call.result_text = _normalise_content(block.get("content"))
                    call.is_error = bool(block.get("is_error", False))

    return SessionTrace(tool_calls=calls, final_text=final_text)


def find_session_jsonl(home: str | Path, session_id: str) -> Path:
    """Locate the session JSONL for ``session_id`` under ``home`` (§0.4).

    Globs ``<home>/.claude/projects/*/<session_id>.jsonl`` -- we do NOT
    reimplement Claude Code's workspace-path-hash encoding. Raises if there is
    not EXACTLY one match (0 means the turn produced no session; >1 means an
    ambiguous home -- both are fail-loud conditions, not silently-scorable).
    """
    home = Path(home)
    matches = list(home.glob(f".claude/projects/*/{session_id}.jsonl"))
    if not matches:
        raise FileNotFoundError(
            f"no session JSONL for session id {session_id!r} under "
            f"{home}/.claude/projects/*/ (agent produced no session?)"
        )
    if len(matches) > 1:
        raise RuntimeError(
            f"ambiguous: {len(matches)} session JSONL files match session id "
            f"{session_id!r} under {home}/.claude/projects/*/: {matches}"
        )
    return matches[0]
