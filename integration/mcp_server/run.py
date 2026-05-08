"""CLI entrypoint: ``python -m integration.mcp_server <config.yaml>``.

Boots the per-agent MCP server from a YAML config:

* loads :class:`ServerConfig` (identity, IPv8 port, MCP port, peers file, …),
* configures structured logging (per-config log file, optional stdout) BEFORE
  any project import triggers the default config,
* awaits :func:`integration.mcp_server.boot.boot` to build a hot
  :class:`ServerState`,
* builds the FastMCP app via :func:`integration.mcp_server.server.build_app`,
* runs the streamable-HTTP server via :meth:`FastMCP.run_async`,
* on shutdown awaits :func:`integration.mcp_server.boot.shutdown` so the
  IPv8 listener releases its UDP port cleanly.

The whole thing is one ``asyncio.run`` call.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def _parse_argv(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m integration.mcp_server",
        description="Boot a DelftClaw MCP server for one agent.",
    )
    parser.add_argument(
        "config",
        type=Path,
        help="Path to the per-agent YAML config (e.g. integration/configs/alice.yaml)",
    )
    return parser.parse_args(argv)


async def _serve(config_path: Path) -> None:
    # Resolve config first so we know the log file before logging configures.
    from integration.mcp_server import config as config_module

    cfg = config_module.load(config_path)

    log_file = cfg.logging.log_file or Path("logs") / f"mcp_{cfg.agent.name}.jsonl"
    from shared.logging import configure_logging

    configure_logging(log_file=log_file, stdout=not cfg.logging.no_stdout)

    # Now safe to import code that uses the project logger at module load.
    from integration.mcp_server.boot import boot, shutdown
    from integration.mcp_server.server import build_app

    print(
        f"DelftClaw MCP server: agent={cfg.agent.name!r} "
        f"network={cfg.agent.network} "
        f"mcp={cfg.mcp_url} "
        f"ipv8={cfg.ipv8.bind_ip}:{cfg.ipv8.bind_port} "
        f"log={log_file}"
    )

    state = await boot(cfg)
    try:
        app = build_app(state)
        await app.run_async(
            transport="streamable-http",
            host=cfg.mcp.bind_ip,
            port=cfg.mcp.bind_port,
        )
    finally:
        await shutdown(state)


def main(argv: list[str] | None = None) -> int:
    args = _parse_argv(argv if argv is not None else sys.argv[1:])
    try:
        asyncio.run(_serve(args.config))
    except KeyboardInterrupt:
        print("\ninterrupted; shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
