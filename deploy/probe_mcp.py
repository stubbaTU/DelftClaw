"""MCP streamable-HTTP client helper for setup + scenario boot.

Two modes:

  python -m deploy.probe_mcp <URL>
      Print the names of every tool the server exposes (default behaviour;
      used by the bootstrap smoke check).

  python -m deploy.probe_mcp <URL> --tool <name> --args '{"k":"v"}'
      Call one tool, print its JSON result on stdout. Used by
      deploy.scenario_boot for runtime peer introduction:
          deploy.probe_mcp http://alice:18765/mcp \\
              --tool peer_add \\
              --args '{"host":"...","port":8191,"pubkey_hex":"..."}'

A real MCP client (FastMCP's ``Client``) does the
``initialize`` → ``initialized`` handshake; a curl POST against
``tools/call`` without it returns 400.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from fastmcp import Client


async def _list_tools(url: str) -> int:
    async with Client(url) as client:
        tools = await client.list_tools()
    for t in tools:
        print(t.name)
    return 0


async def _call_tool(url: str, tool: str, args: dict) -> int:
    async with Client(url) as client:
        result = await client.call_tool(tool, args)
    # FastMCP returns either a CallToolResult with .content list of text/json
    # blocks, or .structured_content. Render whichever is non-empty.
    if getattr(result, "content", None):
        for block in result.content:
            text = getattr(block, "text", None)
            if text is not None:
                print(text)
            else:
                print(repr(block))
    elif getattr(result, "structured_content", None) is not None:
        print(json.dumps(result.structured_content, default=str))
    else:
        print(json.dumps(getattr(result, "data", None), default=str))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m deploy.probe_mcp")
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:8765/mcp",
                        help="MCP streamable-HTTP endpoint")
    parser.add_argument("--tool", help="call this tool (default: list tools)")
    parser.add_argument("--args", default="{}",
                        help="JSON object of arguments for --tool")
    cli = parser.parse_args()

    if cli.tool is None:
        return asyncio.run(_list_tools(cli.url))
    try:
        args = json.loads(cli.args)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"probe_mcp: --args is not valid JSON: {exc}\n")
        return 2
    if not isinstance(args, dict):
        sys.stderr.write(f"probe_mcp: --args must be a JSON object, got {type(args).__name__}\n")
        return 2
    return asyncio.run(_call_tool(cli.url, cli.tool, args))


if __name__ == "__main__":
    raise SystemExit(main())
