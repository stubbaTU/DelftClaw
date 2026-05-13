"""Entry point for running the identity MCP tool server."""

from __future__ import annotations

import argparse
import signal
import sys

import uvicorn

from identity.mcp_server import IdentityMCPServer, default_port


def main() -> None:
    """Load/create AgentIdentity and serve MCP tools over localhost HTTP."""
    parser = argparse.ArgumentParser(description="Run OpenClaw identity MCP server")
    parser.add_argument("--network", choices=["regtest", "testnet", "mainnet"], default="regtest")
    parser.add_argument("--port", type=int, default=default_port())
    parser.add_argument("--identity-path", default="identity/agent_identity.json")
    args = parser.parse_args()

    server = IdentityMCPServer.boot(identity_path=args.identity_path, network=args.network.upper())
    app = server.create_app()

    print(f"Agent ID: {server.tools.identity.get_identity_hash()}")
    print(f"Wallet:   {server.tools.identity.wallet.address()}")
    print(f"Network:  {server.tools.identity.network}")
    print(f"MCP:      http://localhost:{args.port}/mcp")

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

