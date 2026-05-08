# Phase 0 — OpenClaw bench check ✅ PASSED 2026-05-07

This directory holds three throwaway artifacts that verified **OpenClaw can
discover and call a localhost streamable-HTTP MCP server**. The check passed
end-to-end — see "Verified outcome" below. M3 proceeds to Phase 1.

The artifacts stay in place as a known-good reference: if the real M3 server
ever misbehaves, run `bench/verify_with_python_client.py` to isolate the
problem to "OpenClaw or our server".

## What's in here

- **`ping_server.py`** — 30-line FastMCP server exposing one tool, `ping`.
  Runs on `http://127.0.0.1:8080/mcp` (no trailing slash; FastMCP redirects
  `/mcp/` with a 307 — important: register the URL **without** the slash).
- **`mcp_config.test.json`** — superseded by the `openclaw config set` CLI
  approach below; kept for reference, no longer needed.
- **`verify_with_python_client.py`** — sanity check the server is reachable
  *without* OpenClaw. Useful for diagnosing if OpenClaw gets stuck.

## Verified procedure (what actually worked)

OpenClaw 2026.5.6 stores all config in a single file at
`~/.openclaw/openclaw.json` and **does not honour an `OPENCLAW_HOME` env var**.
There is no separate `mcp_config.json` — MCP servers go inside the main
config under `mcp.servers`.

The CLI is the cleanest registration path. Steps that passed on the dev
laptop:

```bash
# 1. Install OpenClaw
curl -fsSL https://openclaw.ai/install.sh | bash
# (or `npm install -g openclaw`)
openclaw --version  # confirm

# 2. Make sure Ollama is running and has a model OpenClaw can use.
#    OpenClaw defaults to qwen2.5:14b — pull that or pick a smaller model
#    and override the default.
ollama serve &                      # in another terminal if not already
ollama pull qwen2.5:14b              # ~9 GB — works out of the box
# OR — pick a smaller model and override:
ollama pull qwen2.5:7b
openclaw config set model.default ollama/qwen2.5:7b

# 3. Register the bench MCP server
openclaw config set mcp.servers.delftclaw-bench \
  '{"url":"http://127.0.0.1:8080/mcp","transport":"streamable-http"}'

# 4. Verify registration
openclaw mcp list
# Should print:
#   MCP servers (/home/<user>/.openclaw/openclaw.json):
#   - delftclaw-bench

# 5. In one terminal, start the bench server
cd <DelftClaw repo root>
. venv/bin/activate
python bench/ping_server.py        # leave running; serves on 127.0.0.1:8080

# 6. In another terminal, start an OpenClaw chat session
openclaw chat                      # opens the TUI

# 7. In the chat, ask:
#    "Please call the ping tool with message 'hello from openclaw' and
#     tell me what you got back."
#
#    Expected response (paraphrased): the agent reports back the echoed
#    message, the server_name "delftclaw-bench", and a server_time_ms
#    Unix-millisecond timestamp.
```

## Verified outcome

```
User: Please call the ping tool with message "hello from openclaw"
      and tell me what you got back.

Agent: The ping tool responded with the message you sent, "hello from
       openclaw". The server's timestamp when it received the message
       was 1778190647655 milliseconds since the Unix epoch. The server
       is named "delftclaw-bench".
```

Every link in the chain confirmed:

```
chat → OpenClaw → qwen2.5 → tool decision → MCP/streamable-http
     → 127.0.0.1:8080/mcp → FastMCP → ping handler
     → {echoed, server_name, server_time_ms} → agent → user
```

## Lessons learned (apply these to Phase 1)

- **Config path:** `~/.openclaw/openclaw.json` (single file, not
  `mcp_config.json`). No `OPENCLAW_HOME` env var.
- **Two-agent demo plan needs a different isolation strategy.** Since
  there's no `OPENCLAW_HOME`, running two OpenClaw instances on one machine
  needs another approach — separate Linux user accounts, or just run them
  serially and reset config between. To revisit at the start of Phase 5.
- **CLI registration:** `openclaw config set mcp.servers.<name> '<json>'`
  works for nested values; pass the inner object as a single JSON string.
- **URL slash matters:** FastMCP serves at `/mcp` and 307-redirects from
  `/mcp/`. Register **without** the trailing slash. (FastMCP-side detail —
  not OpenClaw's fault.)
- **Default model is `qwen2.5:14b`.** Either pull it or `openclaw config
  set model.default ollama/<smaller>`. Without a working model every chat
  turn fails before the tool layer is reached.
- **Chat surface vs control surface.** `openclaw chat` opens the agent
  session that can use MCP tools. The doctor / status / "Gateway"
  responses are the OpenClaw control assistant which has a fixed toolset.

## Cleanup (optional)

The bench server stays useful as a smoke test. To remove the registration:

```bash
openclaw config unset mcp.servers.delftclaw-bench   # if available
# or edit ~/.openclaw/openclaw.json directly and remove the entry
```

The `~/.openclaw-bench/` directory was unused (env var ignored) — safe to
delete:

```bash
rm -rf ~/.openclaw-bench
```
