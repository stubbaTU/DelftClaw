"""Verify the bench ping server end-to-end using FastMCP's Python client.

If this script prints "BENCH OK" you have proven that the streamable-HTTP
MCP server can be reached, lists `ping`, and round-trips a tool call. The
final hop (a real OpenClaw runtime) still has to be confirmed manually,
but if THIS fails we know the issue is on our side, not OpenClaw's.

Run (with the bench server already running on :8080):
    python bench/verify_with_python_client.py
"""

from __future__ import annotations

import asyncio

from fastmcp import Client


async def main() -> None:
    async with Client("http://127.0.0.1:8080/mcp") as client:
        tools = await client.list_tools()
        names = [t.name for t in tools]
        print(f"tool list: {names}")
        assert "ping" in names, f"expected 'ping' in tool list, got {names}"

        result = await client.call_tool("ping", {"message": "from-bench-client"})
        print(f"ping result: {result.data}")
        assert result.data["echoed"] == "from-bench-client"
        assert result.data["server_name"] == "delftclaw-bench"
        assert "server_time_ms" in result.data

    print("BENCH OK")


if __name__ == "__main__":
    asyncio.run(main())
