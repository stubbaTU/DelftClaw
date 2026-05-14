"""Single-process agent runtime: IPv8 + wallet + torrent + overlay registry.

Two consumer paths share the same ``OpenClawAgent`` runtime + ``build_tools``
tool surface:

  - ``agent.mcp_server.build_mcp_server`` — production path. Exposes the 12
    tools over FastMCP streamable-HTTP for OpenClaw chat sessions to call.
  - ``agent.loop.run_tool_loop`` — offline-test path. Internal LLM tool-call
    loop used by the test suite and by ``examples/run_two_agents.py``.
"""

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
    if name == "P2PAgent":
        # The colleague's legacy root-level ``agent.py`` is shadowed by
        # this package on import. Load it explicitly via the file path
        # so the migration test (`from agent import P2PAgent`) collects
        # without us editing the colleague's source. Implementing the
        # Phase C green step is the colleague's responsibility; we only
        # unblock collection here.
        import importlib.util
        from pathlib import Path
        agent_py = Path(__file__).resolve().parent.parent / "agent.py"
        spec = importlib.util.spec_from_file_location("_root_agent_py", agent_py)
        if spec is None or spec.loader is None:
            raise ImportError(f"could not load root-level agent.py at {agent_py}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.P2PAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
