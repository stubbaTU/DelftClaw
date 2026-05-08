"""Throwaway MCP server for the Phase-0 OpenClaw bench check.

Serves a single ``ping`` tool over streamable-HTTP on 127.0.0.1:8080. Boots in
under a second, no project dependencies. If OpenClaw lists this tool and a
chat session can call it round-trip, the M3 plan's transport choice is
validated and we proceed to Phase 1.

Run:
    cd DelftClaw
    . venv/bin/activate
    python bench/ping_server.py

Then point an OpenClaw instance at ``http://127.0.0.1:8080/mcp/`` per the
README in this folder.
"""

from __future__ import annotations

import time

from fastmcp import FastMCP

mcp = FastMCP(
    name="delftclaw-bench",
    instructions=(
        "Throwaway bench-check MCP server for DelftClaw M3-Phase-0. "
        "Exposes a single 'ping' tool to verify OpenClaw can discover and "
        "call a localhost streamable-HTTP MCP server."
    ),
)


@mcp.tool()
def ping(message: str = "pong") -> dict:
    """Return the message and a server timestamp.

    Args:
        message: Any string the LLM wants echoed back. Defaults to "pong".

    Returns:
        A dict with ``echoed`` (the input message), ``server_name`` (a
        constant identifier for the bench server), and ``server_time_ms``
        (the current Unix epoch time in milliseconds). Use this to confirm
        the round-trip works and the server is alive.
    """
    return {
        "echoed": message,
        "server_name": "delftclaw-bench",
        "server_time_ms": int(time.time() * 1000),
    }


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=8080,
    )
