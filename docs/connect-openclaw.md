# Connecting Real OpenClaw Agents

The shared contract is the DelftClaw gateway, not Telegram. Telegram, CLI, or any
other frontend should call the same local HTTP API through OpenClaw tools.

## 1. Start DelftClaw Gateway

```powershell
python -m security.integration.gateway --env configs/yourName.env
```

For everyone, copy `configs/yourName.env` to another local file and use
different ports and agent ids.

## 2. Add OpenClaw Tools

Expose tools in your OpenClaw agent that call `DelftClawClient`:

```python
from security.integration import DelftClawClient

client = DelftClawClient()

def delftclaw_send_message(recipient: str, message: str):
    return client.send_message(recipient, message)

def delftclaw_register_seedbox(seedbox_id: str, donation_address: str, advertised_capacity_gb: int):
    return client.register_seedbox(seedbox_id, donation_address, advertised_capacity_gb)

def delftclaw_broadcast_seedbox_donation(seedbox_id: str, amount_sats: int):
    return client.broadcast_seedbox_donation(seedbox_id, amount_sats)
```

The OpenClaw model may propose the tool call, but DelftClaw decides whether the
action executes, gets logged, or triggers reputation penalties.

## 3. Useful Gateway Endpoints

```text
POST /tool-call
POST /donation
POST /security-report
GET  /health
GET  /metrics
GET  /reputation/{agent_id}
```

Example tool-call body:

```json
{
  "agent_id": "name-agent",
  "tool_name": "broadcast_seedbox_donation",
  "tool_kwargs": {
    "seedbox_id": "seedbox-1",
    "amount_sats": 10000
  },
  "source": "openclaw-telegram",
  "payload_id": "torrent_001"
}
```

## 4. Experiment Modes

Use `DELFTCLAW_GATEWAY_MODE=baseline` to measure unsafe execution.
Use `DELFTCLAW_GATEWAY_MODE=defended` to measure the security architecture.

Keep every teammate on their own `DELFTCLAW_AGENT_ID`, gateway port, P2P port,
and log path.
