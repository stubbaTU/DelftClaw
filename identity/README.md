# Identity Layer

This folder contains the cryptographic identity stack for autonomous OpenClaw agents.

## Run MCP identity server

```bash
python -m identity.start_identity_server --network regtest --port 7701 --identity-path identity/agent_identity.json
```

## MCP config

Use `identity/openclaw_mcp_config.json` in your OpenClaw MCP client config.

## Tests

```bash
pytest identity/tests -q
```

