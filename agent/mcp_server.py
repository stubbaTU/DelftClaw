"""FastMCP streamable-HTTP server wrapping the agent's tool surface.

Single source of truth: ``agent.tools.build_tools(agent)`` produces the
``ToolRegistry`` used by every other call path (the in-process loop in
``agent/loop.py`` and now this MCP server). We register every entry of
that registry verbatim — no hand-translation, no surface drift.

Previously this module re-declared each tool by hand and silently
dropped the v5.2 community + comms additions (``community_join_via_peer``,
``wallet_send``, ``community_treasury_balance``, ``community_member_count``,
``community_log_list_recent``, ``seedbox_purchase_propose``,
``seedbox_provisioned``, ``overlay_publish``). Driving the agent over
MCP without those tools made the LLM unable to actually trigger any
wire-side admission flow, even when the snapshot said it should. The
collapse onto ``build_tools`` closes that gap by construction.

There are still **two LLMs** in the picture, and they do not overlap:

  - **OpenClaw's LLM** (whatever model OpenClaw is configured with) —
    the agent's brain. Decides *which* tool to call. Talks to this
    server over MCP.
  - **The compiler LLM** (e.g. Qwen on the supervisor's GPU host) —
    called by ``OverlayRegistry`` *only* when this node needs to
    compile a ``.md`` overlay descriptor it has never seen before.
    Configured via ``--llm-base-url`` / ``--llm-model`` on the agent
    side. Never talks to OpenClaw.

Boot via ``python -m agent ... mcp --mcp-host 0.0.0.0 --mcp-port 8765``.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import time
from typing import Any, Callable

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_context
from fastmcp.tools import Tool as FastMCPTool

from agent.runtime import OpenClawAgent
from agent.tools import build_tools


_tool_logger = logging.getLogger("delftclaw.agent.tools")


# ---------------------------------------------------------------------------
# Per-session tool-call budget
# ---------------------------------------------------------------------------
#
# OpenClaw + Haiku ignore the HARD RULE in the turn prompt and routinely
# fire 7-8 tool calls per MCP session (== one watchdog turn). Each one
# costs a Haiku round-trip, blows through the Anthropic Tier-1 token
# budget, and stretches the watchdog turn lock past a minute.
#
# We enforce one-tool-per-turn at the MCP layer instead. The first call
# in a session runs normally; subsequent calls short-circuit with a
# ``tool_budget_exhausted`` error that tells the model exactly what to
# do next. Soft enforcement — the model can still ignore the error and
# call again, but every extra call returns the same error so the cost
# is bounded to "openclaw gives up and produces text."
#
# Budget keyed by FastMCP's per-session id. ``MCP_TOOL_BUDGET_PER_SESSION``
# env override exists so a turn that genuinely needs multiple tools
# (e.g. ``overlay_fetch_and_load`` THEN ``overlay_invoke``) can be
# unlocked from scenario.yaml without a code change.

DEFAULT_TOOL_BUDGET_PER_SESSION = 1


def _budget_per_session() -> int:
    try:
        n = int(os.environ.get("MCP_TOOL_BUDGET_PER_SESSION", DEFAULT_TOOL_BUDGET_PER_SESSION))
    except (TypeError, ValueError):
        return DEFAULT_TOOL_BUDGET_PER_SESSION
    return max(1, n)


# Read-only / introspection tools that DO NOT count toward the per-session
# budget. The point of the budget is to stop the LLM from emitting
# multiple state-changing actions per turn (donate, send, invoke, ...).
# Letting it freely query state is exactly the pattern we want — fetch
# the snapshot, decide, do one thing. It also lets the watchdog's
# ``deploy.mcp_snapshot.collect_state_via_mcp`` issue its 6 sequential
# introspection calls inside a single MCP session without tripping the
# gate (the watchdog snapshot is a SEPARATE caller from openclaw and
# should not consume the LLM's budget at all).
_BUDGET_FREE_TOOLS: frozenset[str] = frozenset({
    # local-node introspection
    "peers_list",
    "wallet_address",
    "wallet_balance",
    # community-state reads (replay over signed log + peer log)
    "community_treasury_balance",
    "community_member_count",
    "community_log_list_recent",
    # overlay metadata reads
    "overlays_list",
    "overlay_describe",
    # torrent / bittorrent reads
    "torrent_stats",

    # regtest / on-chain BTC reads
    "btc_get_balance",
    "btc_list_utxos",
    "btc_list_transactions",
    "btc_transaction_status",
})


# Counter: session_id -> tool calls already served this session. Only
# ``write`` tools (anything not in ``_BUDGET_FREE_TOOLS``) increment it.
# FastMCP's session manager terminates the underlying transport ~30s
# after the last call, so leaks are bounded even without explicit cleanup.
_SESSION_TOOL_COUNT: dict[str, int] = {}


def _exposed_tool_allowlist() -> set[str] | None:
    """Optional comma-separated MCP tool allowlist from the environment.

    Some OpenAI-compatible local model servers reject large MCP/tool payloads.
    Deployment can set ``MCP_EXPOSE_TOOLS`` to a minimal scenario-specific
    surface while keeping the in-process registry unchanged.
    """
    raw = os.environ.get("MCP_EXPOSE_TOOLS", "").strip()
    if not raw:
        return None
    allowed = {part.strip() for part in raw.split(",") if part.strip()}
    return allowed or None


def _session_id_or_global() -> str:
    """Return the current MCP session id, or ``"__global__"`` as a fallback.

    FastMCP's ``get_context()`` raises outside a request scope; this
    happens in tests that invoke ``add_tool``'d functions directly. The
    fallback lets the same wrapper be used in-process without surprise.
    """
    try:
        return get_context().session_id or "__global__"
    except Exception:
        return "__global__"


def _short(value: Any, n: int = 80) -> str:
    """Compact one-line render for the TOOL audit log."""
    try:
        s = json.dumps(value, default=str)
    except (TypeError, ValueError):
        s = str(value)
    return s if len(s) <= n else (s[: n - 1] + "…")


def _audit_wrap(name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    """Return an async wrapper around ``fn`` that emits the same TOOL
    log lines ``ToolRegistry.dispatch`` does for the in-process path,
    and enforces the per-session tool-call budget.

    FastMCP introspects the wrapped function's signature for its JSON
    schema, so ``functools.wraps`` is load-bearing — it preserves the
    parameter annotations FastMCP needs. Errors are caught and returned
    as ``{"error": ...}`` to match the in-process dispatch contract,
    so a buggy tool surfaces in the MCP response payload rather than
    crashing the streamable-HTTP session.
    """
    is_free = name in _BUDGET_FREE_TOOLS

    @functools.wraps(fn)
    async def wrapper(**kwargs: Any) -> Any:
        budget = _budget_per_session()
        session_id = _session_id_or_global()
        served = _SESSION_TOOL_COUNT.get(session_id, 0)

        # Read-only tools (peers_list, wallet_balance, *_list, etc.)
        # bypass the budget entirely. They don't drive LLM state changes
        # and the watchdog snapshot legitimately needs to call several
        # of them inside one MCP session every tick.
        if not is_free and served >= budget:
            _tool_logger.warning(
                "TOOL skip name=%s reason=budget session=%s served=%d budget=%d",
                name, session_id[:8], served, budget,
            )
            # ``ToolError`` is FastMCP's way to surface a tool-side
            # failure to the model without violating the declared
            # output_schema (the LLM-driven tools have typed returns
            # like ``int`` for wallet_balance; an envelope dict would
            # be rejected by the MCP client's schema validator).
            raise ToolError(
                f"tool_budget_exhausted: you have already used your "
                f"{budget} state-changing tool call this turn. STOP calling "
                "tools and produce your final assistant message now — the "
                "harness will wake you again with a fresh budget on the "
                "next tick. (Read-only tools like peers_list / wallet_balance "
                "/ overlays_list / community_treasury_balance are free.)"
            )

        t0 = time.monotonic()
        kind = "free" if is_free else f"{served + 1}/{budget}"
        _tool_logger.info(
            "TOOL call name=%s session=%s budget=%s args=%s",
            name, session_id[:8], kind, _short(kwargs),
        )
        # Only state-changing calls consume budget. Reserve the slot
        # BEFORE awaiting so a concurrent second call racing inside the
        # same session also trips the cap.
        if not is_free:
            _SESSION_TOOL_COUNT[session_id] = served + 1
        try:
            result = await fn(**kwargs)
            _tool_logger.info(
                "TOOL ok   name=%s session=%s elapsed=%.3fs result=%s",
                name, session_id[:8], time.monotonic() - t0, _short(result),
            )
            return result
        except ToolError:
            # Let the budget guard (or any tool-emitted ToolError) flow
            # back to the client untouched so it materialises as an
            # ``isError=true`` MCP response instead of getting buried in
            # a generic envelope dict that the client may schema-reject.
            raise
        except Exception as exc:
            _tool_logger.warning(
                "TOOL fail name=%s session=%s elapsed=%.3fs error=%s: %s",
                name, session_id[:8], time.monotonic() - t0,
                type(exc).__name__, exc,
            )
            # Surface unexpected tool failures the same way — the
            # in-process ToolRegistry returns an envelope dict, but
            # over MCP we want a typed error so the model sees a
            # clear failure signal rather than a {"error": …} payload
            # that fights the output_schema. The in-process path is
            # unaffected because it never goes through this wrapper.
            raise ToolError(f"{type(exc).__name__}: {exc}")

    return wrapper


SERVER_INSTRUCTIONS = """\
DelftClaw agent tools. Use these to operate on the P2P content network.

Surface mirrors the in-process tool registry exactly — every tool the
in-process loop can call is also callable over this MCP server. Highlights:

  - peers_list / wallet_address / wallet_balance — local-node introspection.
  - community_donate_and_join — write a signed donation_intent entry to
    the local log. Treasury balance, member count, and threshold status
    are already in the state snapshot under ``community`` so no extra
    tool call is needed to read them.
  - community_join_via_peer — END-TO-END admission: writes the entry
    locally AND ships it to the gatekeeper over the wire. Use this once
    a gatekeeper peer is reachable (peer_add or genesis-peer listing).
  - overlays_list — every loaded overlay's full per-message field schema
    and handler text. Read this before calling overlay_invoke.
  - overlay_fetch_and_load — pull a descriptor from a peer by md_hash and
    compile + register it. After this returns, overlay_invoke works.
  - overlay_invoke — send a message defined by a compiled overlay.
  - torrent_* — fetch/seed by magnet URI.

If you receive an unfamiliar md_hash from a peer, fetch+load the
descriptor first before trying to invoke it.
"""


def build_mcp_server(agent: OpenClawAgent, *, name: str = "delftclaw-agent") -> FastMCP:
    """Wrap an ``OpenClawAgent`` as a FastMCP server.

    Iterates the in-process ``ToolRegistry`` so every tool the LLM-loop
    can call is also exposed over MCP. Each tool's callable already
    carries typed-async signatures, which FastMCP turns into the
    OpenAI-style JSON schema; the operator-facing ``description`` from
    the registry entry is forwarded verbatim.
    """
    mcp = FastMCP(name=name, instructions=SERVER_INSTRUCTIONS)
    registry = build_tools(agent)
    allowed = _exposed_tool_allowlist()
    for tool in registry._tools.values():
        if allowed is not None and tool.name not in allowed:
            continue
        # Wrap each registry callable so MCP-dispatched calls produce
        # the same ``TOOL call name=… args=…`` / ``TOOL ok …`` /
        # ``TOOL fail …`` audit lines that ``ToolRegistry.dispatch``
        # emits for the in-process path. Without the shim the MCP route
        # silently bypasses ``dispatch`` and the operator loses the
        # audit trail — the previous symptom was "0 tool calls in
        # journalctl" even though IPv8 wire traffic proved tools were
        # actually firing.
        mcp.add_tool(
            FastMCPTool.from_function(
                _audit_wrap(tool.name, tool.fn),
                name=tool.name,
                description=tool.description,
            )
        )
    return mcp


async def serve_mcp_async(
    agent: OpenClawAgent,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> None:
    """Build the MCP server and serve it over streamable-HTTP until cancelled.

    Streamable-HTTP is the transport OpenClaw uses; ``--mcp-host 0.0.0.0``
    + a firewall opening on ``port`` is what a VPS deployment looks like.
    """
    mcp = build_mcp_server(agent)
    await mcp.run_async(transport="streamable-http", host=host, port=port)
