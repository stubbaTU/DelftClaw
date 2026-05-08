"""Allow ``python -m integration.mcp_server <config.yaml>`` to boot the server."""

from integration.mcp_server.run import main

if __name__ == "__main__":
    raise SystemExit(main())
