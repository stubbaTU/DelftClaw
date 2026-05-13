from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from security.integration.openclaw_tools import TOOL_REGISTRY, EXPERIMENT_ONLY_TOOL_REGISTRY, tool_manifest


class ToolCall(BaseModel):
    args: dict[str, Any] = {}


class SecurityToolServer:
    """MCP-style facade over the DelftClaw security gateway tools."""

    def __init__(self, *, include_experiment_only: bool = False) -> None:
        self.include_experiment_only = include_experiment_only
        self.tools = dict(TOOL_REGISTRY)
        if include_experiment_only:
            self.tools.update(EXPERIMENT_ONLY_TOOL_REGISTRY)

    def manifest(self) -> dict[str, Any]:
        return {
            "server": "delftclaw-security",
            "tools": [spec["name"] for spec in tool_manifest(self.include_experiment_only)],
        }

    def call_tool(self, tool_name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        tool = self.tools.get(tool_name)
        if tool is None:
            return {"ok": False, "error": f"unknown tool: {tool_name}"}
        try:
            return tool(**(args or {}))
        except TypeError as exc:
            return {"ok": False, "error": f"invalid arguments for {tool_name}: {exc}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


class SecurityMCPServer:
    """HTTP app exposing security tools through the same MCP shape as identity."""

    def __init__(self, tool_server: SecurityToolServer | None = None) -> None:
        self.tools = tool_server or SecurityToolServer()

    def create_app(self) -> FastAPI:
        app = FastAPI(title="DelftClaw Security MCP", version="1.0")

        @app.get("/health")
        def health() -> dict[str, Any]:
            return {"ok": True}

        @app.get("/mcp")
        def manifest() -> dict[str, Any]:
            return self.tools.manifest()

        @app.post("/mcp/tool/{tool_name}")
        def call_tool(tool_name: str, req: ToolCall) -> dict[str, Any]:
            return self.tools.call_tool(tool_name, req.args)

        return app


def app(include_experiment_only: bool = False) -> FastAPI:
    return SecurityMCPServer(SecurityToolServer(include_experiment_only=include_experiment_only)).create_app()
