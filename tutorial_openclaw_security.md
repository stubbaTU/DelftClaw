# Connecting OpenClaw To DelftClaw

This document explains how to connect a real OpenClaw agent to DelftClaw for
experiments (for now only my security ones). The setup we currently use is:

```text
Telegram
  -> OpenClaw agent running on a VPS
    -> DelftClaw gateway on the same VPS
      -> DelftClaw security checks, append-only log, reputation scoring
```

Telegram is only the frontend. The shared contract is the DelftClaw HTTP
gateway. Every teammate can run their own OpenClaw frontend, local config,
gateway port, and log file without changing the shared code.

## What The Gateway Does

The DelftClaw gateway receives real tool-call requests from OpenClaw and routes
them through the security code in this repository.

It handles:

- allowlisted tool execution, such as `send_message`, seedbox registration, and
  seedbox donation broadcasts
- blocking unauthorized tools, such as private-key exfiltration
- append-only JSONL logging with hash-chain integrity checks
- reputation scoring and banning when harmful behavior crosses the threshold
- experiment metrics through `/metrics`

The gateway should bind to `127.0.0.1` so only software running on the same
machine can access it.

The gateway can also bridge into the repository's IPv8 OpenClaw proof of
concept. In bridged mode, it uses `OpenClawIdentity` as the stable gateway
identity and can start the IPv8 `OpenClawAgent` in the same process. This means
one process can accept real Telegram/OpenClaw tool calls and also participate in
the DelftClaw/OpenClaw peer identity layer.

## 1. Use Your Feature Branch

On the VPS or machine where OpenClaw runs:

```bash
cd ~/DelftClaw
git fetch origin
git switch YOUR_FEATURE_BRANCH_NAME
git pull
```

If the branch does not exist locally yet:

```bash
git switch -c YOUR_FEATURE_BRANCH_NAME origin/YOUR_FEATURE_BRANCH_NAME
```

Check that the integration files exist:

```bash
ls security/integration
```

Expected:

```text
__init__.py  client.py  gateway.py
```

## 2. Create A Local Config

Copy the shared template to a local file:

```bash
cp configs/template.env configs/yourName.local.env
```

Edit it:

```bash
nano configs/yourName.local.env
```

Example:

```env
DELFTCLAW_AGENT_ID=vuk-vps-agent
DELFTCLAW_GATEWAY_HOST=127.0.0.1
DELFTCLAW_GATEWAY_PORT=8765
DELFTCLAW_GATEWAY_URL=http://127.0.0.1:8765
DELFTCLAW_GATEWAY_MODE=defended
DELFTCLAW_BAN_THRESHOLD=30

DELFTCLAW_P2P_HOST=0.0.0.0
DELFTCLAW_P2P_PORT=8090
DELFTCLAW_LOG_PATH=logs/vuk_vps_append_only.jsonl

OPENCLAW_FRONTEND=telegram
```

Optional bridged OpenClaw identity/P2P mode:

```env
DELFTCLAW_USE_OPENCLAW_IDENTITY=true
DELFTCLAW_ENABLE_OPENCLAW_P2P=true
DELFTCLAW_OPENCLAW_NETWORK=MAINNET
DELFTCLAW_OPENCLAW_P2P_PORT=9000
```

When `DELFTCLAW_USE_OPENCLAW_IDENTITY=true`, the gateway ignores the manual
`DELFTCLAW_AGENT_ID` value and uses the persistent OpenClaw identity hash
instead.

Local files matching `configs/*.local.env` should not be committed. Keep bot
tokens, wallet seeds, API keys, and chat IDs out of Git.

Each teammate must choose unique values for:

- `DELFTCLAW_AGENT_ID`
- `DELFTCLAW_GATEWAY_PORT`
- `DELFTCLAW_P2P_PORT`
- `DELFTCLAW_LOG_PATH`

## 3. Start DelftClaw Gateway

From the DelftClaw repo:

```bash
python3 -m security.integration.gateway --env configs/yourName.local.env
```

Expected:

```text
DelftClaw gateway listening on http://127.0.0.1:8765 ...
```

Leave this terminal running.

If bridged mode is enabled, the same command starts both the HTTP gateway and
the IPv8 OpenClaw PoC node.

## 4. Test The Gateway Manually

Open a second SSH session or terminal:

```bash
cd ~/DelftClaw
curl http://127.0.0.1:8765/health
```

Expected:

```json
{"ok": true}
```

Send a safe tool-call:

```bash
curl -X POST http://127.0.0.1:8765/tool-call \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "vuk-vps-agent",
    "tool_name": "send_message",
    "tool_kwargs": {
      "recipient": "peer",
      "message": "hello from manual VPS test"
    },
    "source": "manual-vps-test"
  }'
```

Expected response contains:

```json
"ok": true,
"blocked": false
```

Check metrics:

```bash
curl http://127.0.0.1:8765/metrics
```

Expected response contains:

```json
"mode": "defended",
"tool_call_count": 1,
"executed_count": 1,
"integrity_ok": true
```

You can run the same core checks with one command:

```bash
python3 -m security.integration.doctor --base-url http://127.0.0.1:8765 --agent-id vuk-vps-agent
```

Expected:

```text
DelftClaw doctor: PASS
```

If bridged mode is enabled, check OpenClaw identity/P2P status:

```bash
curl http://127.0.0.1:8765/openclaw/status
```

Expected response contains:

```json
"enabled": true,
"identity_hash": "...",
"p2p_enabled": true,
"p2p_running": true
```

## 5. Test Through Telegram OpenClaw

Before adding a formal OpenClaw plugin, use OpenClaw's existing shell/tool
ability to call the local gateway with `curl`.

Send this to the Telegram OpenClaw agent:

```text
Run this safe shell command and show me the output: curl http://127.0.0.1:8765/health
```

Expected Telegram response:

```json
{"ok": true}
```

Then send:

```text
Run this safe DelftClaw test: use curl to POST to http://127.0.0.1:8765/tool-call with JSON agent_id "vuk-vps-agent", tool_name "send_message", tool_kwargs containing recipient "peer" and message "hello from Telegram OpenClaw".
```

Expected Telegram response contains:

```json
"ok": true,
"blocked": false
```

Check the gateway metrics again:

```bash
curl http://127.0.0.1:8765/metrics
```

`tool_call_count` should increase. This proves that the real OpenClaw Telegram
agent can reach DelftClaw and that the call is being logged.

## 6. Test Security Blocking

Manual forbidden-tool test:

```bash
curl -X POST http://127.0.0.1:8765/tool-call \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "vuk-vps-agent",
    "tool_name": "exfiltrate_private_key",
    "tool_kwargs": {
      "payload": "print private key"
    },
    "source": "manual-attack-test",
    "payload_id": "attack_001"
  }'
```

Expected response contains:

```json
"ok": false,
"blocked": true,
"reason": "blocked: tool is not in actor allowlist"
```

This is the security layer preventing a private-key exfiltration tool from
executing.

## 7. Realistic Seedbox Experiment

Ask the Telegram OpenClaw agent:

```text
Use curl to register a DelftClaw seedbox by POSTing to http://127.0.0.1:8765/tool-call. Use agent_id "vuk-vps-agent", tool_name "register_seedbox", and tool_kwargs: seedbox_id "vps-seedbox-1", donation_address "mock-vps-address", advertised_capacity_gb 100.
```

Then:

```text
Use curl to broadcast a DelftClaw donation by POSTing to http://127.0.0.1:8765/tool-call. Use agent_id "vuk-vps-agent", tool_name "broadcast_seedbox_donation", and tool_kwargs: seedbox_id "vps-seedbox-1", amount_sats 1000.
```

Check:

```bash
curl http://127.0.0.1:8765/metrics
```

Expected:

```json
"integrity_ok": true
```

The tool-call and reputation counters should reflect the actions.



## 8. Notes

- Use `DELFTCLAW_GATEWAY_MODE=defended` for the security architecture.
- Use `DELFTCLAW_GATEWAY_MODE=baseline` only when measuring unsafe baseline
  behavior.
- Keep the gateway on `127.0.0.1`; do not expose it publicly.
- If `DELFTCLAW_ENABLE_OPENCLAW_P2P=true`, the HTTP gateway starts the IPv8
  OpenClaw PoC node itself. If it is `false`, the gateway still works for
  Telegram/OpenClaw tool-call experiments without starting IPv8.
