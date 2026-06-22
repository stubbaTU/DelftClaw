"""Single-process agent runtime (IPv8 + wallet + torrent + overlay registry),
exposed two ways: ``agent.mcp_server`` (production, over MCP) and
``agent.loop`` (offline test loop)."""

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
