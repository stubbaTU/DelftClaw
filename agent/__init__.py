"""Single-process agent runtime: IPv8 + wallet + torrent + overlay registry.

Two consumer paths share the same ``OpenClawAgent`` runtime + ``build_tools``
tool surface:

  - ``agent.mcp_server.build_mcp_server`` — production path. Exposes the 12
    tools over FastMCP streamable-HTTP for OpenClaw chat sessions to call.
  - ``agent.loop.run_tool_loop`` — offline-test path. Internal LLM tool-call
    loop used by the test suite and by ``examples/run_two_agents.py``.
"""

# Setup libsodium early for Windows compatibility
from agent.libsodium_setup import setup_libsodium
setup_libsodium()

from agent.loop import (
    OpenAICompatibleToolLLM,
    StubToolLoopLLM,
    SYSTEM_PROMPT,
    ToolLoopLLM,
    run_tool_loop,
)
from agent.runtime import AgentConfig, OpenClawAgent
from agent.tools import Tool, ToolRegistry, build_tools

__all__ = [
    "AgentConfig",
    "OpenAICompatibleToolLLM",
    "OpenClawAgent",
    "StubToolLoopLLM",
    "SYSTEM_PROMPT",
    "Tool",
    "ToolLoopLLM",
    "ToolRegistry",
    "build_tools",
    "run_tool_loop",
]


def __getattr__(name: str):
    # Lazy import so ``import agent`` doesn't drag in fastmcp + httpx + starlette.
    if name in ("build_mcp_server", "serve_mcp_async"):
        from agent import mcp_server
        return getattr(mcp_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
