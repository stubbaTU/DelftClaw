from __future__ import annotations

import argparse
import os
import signal
import sys

import uvicorn

from security.integration.mcp_server import SecurityMCPServer, SecurityToolServer


def default_port() -> int:
    return int(os.environ.get("DELFTCLAW_SECURITY_MCP_PORT", "7702"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run DelftClaw security MCP server")
    parser.add_argument("--port", type=int, default=default_port())
    parser.add_argument("--include-experiment-only", action="store_true")
    args = parser.parse_args()

    server = SecurityMCPServer(SecurityToolServer(include_experiment_only=args.include_experiment_only))
    app = server.create_app()

    print(f"MCP: http://localhost:{args.port}/mcp")
    print(f"Tools: {', '.join(server.tools.manifest()['tools'])}")

    config = uvicorn.Config(app, host="127.0.0.1", port=args.port, log_level="warning")
    uv_server = uvicorn.Server(config)

    def _stop(_signum, _frame) -> None:
        uv_server.should_exit = True

    signal.signal(signal.SIGINT, _stop)
    uv_server.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
