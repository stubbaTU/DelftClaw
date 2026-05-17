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
import time
from typing import Any, Callable

from fastmcp import FastMCP
from fastmcp.tools.tool import Tool as FastMCPTool

from agent.runtime import OpenClawAgent
from agent.tools import build_tools


_tool_logger = logging.getLogger("delftclaw.agent.tools")


def _short(value: Any, n: int = 80) -> str:
    """Compact one-line render for the TOOL audit log."""
    try:
        s = json.dumps(value, default=str)
    except (TypeError, ValueError):
        s = str(value)
    return s if len(s) <= n else (s[: n - 1] + "…")


def _audit_wrap(name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    """Return an async wrapper around ``fn`` that emits the same TOOL
    log lines ``ToolRegistry.dispatch`` does for the in-process path.

    FastMCP introspects the wrapped function's signature for its JSON
    schema, so ``functools.wraps`` is load-bearing — it preserves the
    parameter annotations FastMCP needs. Errors are caught and returned
    as ``{"error": ...}`` to match the in-process dispatch contract,
    so a buggy tool surfaces in the MCP response payload rather than
    crashing the streamable-HTTP session.
    """
    @functools.wraps(fn)
    async def wrapper(**kwargs: Any) -> Any:
        t0 = time.monotonic()
        _tool_logger.info("TOOL call name=%s args=%s", name, _short(kwargs))
        try:
            result = await fn(**kwargs)
            _tool_logger.info(
                "TOOL ok   name=%s elapsed=%.3fs result=%s",
                name, time.monotonic() - t0, _short(result),
            )
            return result
        except Exception as exc:
            _tool_logger.warning(
                "TOOL fail name=%s elapsed=%.3fs error=%s: %s",
                name, time.monotonic() - t0, type(exc).__name__, exc,
            )
            return {"error": f"{type(exc).__name__}: {exc}"}

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
    for tool in registry._tools.values():
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
