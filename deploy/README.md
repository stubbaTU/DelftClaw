# DelftClaw — Operator runbook

Target: **Hostinger KVM 2** (Ubuntu 24.04, 8 GB RAM, 2 vCPU).
LLM: **Qwen2.5-Coder 7B via local Ollama** on the same VPS.

## TL;DR — first deploy

```bash
# On your laptop, from the repo root:
make deploy
```

That installs system packages, Ollama, the model, the venv, the
templated systemd units, the firewall rules. Idempotent; re-running is
safe.

After it finishes there is **no agent running**. Agents are launched
per scenario:

```bash
make scenario NAME=seek_cc      # launch the seek_cc scenario
make watch    NAME=seek_cc      # tail every agent's journal
make stop     NAME=seek_cc      # stop and teardown
make scenarios                  # list active scenarios
```

## Makefile targets

| Target | What it runs |
|---|---|
| `make deploy` | `rsync` + `setup_vps.sh` (full infrastructure bootstrap) |
| `make push` | Just rsync — skip the bootstrap |
| `make bootstrap` | Just re-run setup_vps.sh on the VPS |
| `make scenario NAME=…` | `rsync` + `python -m deploy.scenario_boot NAME` |
| `make scenarios` | `systemctl list-units 'delftclaw-{mcp,watchdog}@*.service'` |
| `make watch NAME=…` | `journalctl -fu 'delftclaw-{mcp,watchdog}@NAME-*'` |
| `make stop NAME=…` | `python -m deploy.scenario_boot NAME --teardown` |
| `make ssh` | Open an interactive shell on the VPS |
| `make test` | Run the project pytest suite locally |

Override `VPS_HOST` / `VPS_USER` / `VPS_ROOT` on the command line:

```bash
make scenario VPS_HOST=other.example.com NAME=seek_cc
```

## What `setup_vps.sh` does

One-shot, idempotent, runs as root. Walks through:

1. **apt** — python3-venv, libsodium-dev, build-essential, ufw, jq, git.
2. **Ollama install** — official one-liner, enabled as a systemd service.
3. **Model pull** — `qwen2.5-coder:7b` (override via `QWEN_MODEL=…` env).
4. **User + dirs** — creates `delftclaw` system user, `/var/lib/delftclaw/`, `/var/log/delftclaw/`, `/etc/delftclaw/{instances,scenarios}/`.
5. **venv** — `python3 -m venv` + `pip install -r requirements.txt`.
6. **systemd templates** — installs `delftclaw-mcp@.service` and `delftclaw-watchdog@.service`, removes any legacy non-templated unit.
7. **ufw rules** — adds rules for `22/tcp`, `8190-8199/udp`, `18765-18774/tcp`. Does **not** enable the firewall.
8. **openclaw CLI check** — verifies the watchdog can spawn `openclaw agent` subprocesses.

The single-instance start is gone. Use `make scenario NAME=…` instead.

## How scenarios work

A scenario is a directory under `deploy/scenarios/<name>/`:

```
deploy/scenarios/seek_cc/
├── scenario.yaml         # the manifest (agents, ports, watchdog policy)
├── alice/
│   ├── persona.md        # system-prompt for Alice
│   └── goal.md           # initial goal for Alice
└── bob/
    ├── persona.md
    └── goal.md
```

`make scenario NAME=seek_cc` runs `python -m deploy.scenario_boot
seek_cc` on the VPS:

1. Parses the manifest (strict schema; see `docs/architecture.md` §13).
2. Creates `/var/lib/delftclaw/<scenario>/<agent>/` per agent.
3. Generates a deterministic BIP-39 seed file if missing.
4. Writes per-instance env files under `/etc/delftclaw/instances/`.
5. Stages persona/goal under `/etc/delftclaw/scenarios/<instance>/`.
6. `systemctl enable --now delftclaw-mcp@<instance>` per agent.
7. Waits for each MCP port to come up.
8. Cross-introduces peers via the `peer_add` MCP tool.
9. `systemctl enable --now delftclaw-watchdog@<instance>` per agent.

The watchdog polls every `interval_s` seconds, builds a turn prompt
(persona + goal + state snapshot + history tail), subprocesses
`openclaw agent --agent <instance> --message <prompt> --json`, logs the
result to `/var/log/delftclaw/scenarios/<scenario>/<agent>.jsonl`, and
exits when the stop predicate fires.

### Stop predicates

Resolved by name from `scenario.yaml`. Available (see
`deploy/stop_predicates.py`):

- `never` — always False; long-running seedboxes
- `torrent_progress_gte_1` — any torrent finished
- `peer_count_gte_N(n=…)` — at least N peers
- `wallet_received_sats(min_sats=…)` — balance increased by min_sats

The LLM **does not** decide it's done. The watchdog does.

## Verifying a scenario

```bash
make scenario NAME=seek_cc
make scenarios                  # confirm both agents are up
make watch    NAME=seek_cc      # tail until Bob's watchdog exits 0
```

You should see (with `qwen2.5-coder:7b` on a KVM 2; timings approximate):

```
T+00s   scenario_boot wrote /etc/delftclaw/instances/seek_cc-{alice,bob}.env
T+02s   delftclaw-mcp@seek_cc-alice.service: Started
T+02s   delftclaw-mcp@seek_cc-bob.service:   Started
T+04s   bob.peer_add(alice) OK
T+30s   bob.watchdog turn=1: invokes openclaw agent (cold-load Qwen ~10-30s)
T+90s   bob.watchdog turn=2: state shows admitted=true
...
T+360s  bob.watchdog: stop_predicate_satisfied; exit 0
```

If a watchdog exits non-zero, `make watch` shows the reason; the JSONL
log under `/var/log/delftclaw/scenarios/<name>/<agent>.jsonl` has the
full turn-by-turn trace.

## OpenClaw chat (interactive, optional)

The MCP servers are also reachable from an OpenClaw chat for hand-driven
debugging. The URL is per-agent:

```jsonc
{
  "mcpServers": {
    "delftclaw_seek_cc_alice": {
      "transport": "streamable-http",
      "url": "http://srv1665973.hstgr.cloud:18765/mcp"
    },
    "delftclaw_seek_cc_bob": {
      "transport": "streamable-http",
      "url": "http://srv1665973.hstgr.cloud:18766/mcp"
    }
  }
}
```

The 12 + 1 tools (`peers_list`, `peer_add`, `wallet_*`,
`seedbox_donate_and_join`, `overlays_*`, `overlay_invoke`, `torrent_*`)
become available to the OpenClaw LLM.

## Ports

| Port range | Proto | Direction | Why |
|---|---|---|---|
| 22 | tcp | inbound | SSH |
| 8190-8199 | udp | inbound | IPv8 peer-to-peer (one per agent) |
| 18765-18774 | tcp | inbound | FastMCP streamable-HTTP (one per agent) |
| 11434 | tcp | localhost only | Ollama (do not expose externally) |

Run `ufw enable` only after confirming `ufw status` lists port 22.

## Troubleshooting

```bash
make scenarios                  # systemctl list-units
make watch NAME=…               # journalctl -fu
```

Check the JSONL log:
```bash
make ssh
sudo tail -f /var/log/delftclaw/scenarios/seek_cc/bob.jsonl | jq
```

| Symptom | Likely cause | Fix |
|---|---|---|
| `Connection refused` to Ollama port | `ollama` service not running | `systemctl restart ollama` |
| `model not found` from Ollama | `QWEN_MODEL` doesn't match a pulled tag | `ollama list`; pull with `ollama pull <tag>` |
| Watchdog exits with code 3 | N consecutive `openclaw agent` failures | inspect last turn in the JSONL; check Qwen endpoint health |
| `ProtocolCompileError: test vector encode mismatch` | Qwen produced wire-incompatible code for a new `.md` | tighten `protocol/compiler.py:SYSTEM_PROMPT`; or pre-load via stub source |
| Bob's wallet shows 0 sats indefinitely | scenario doesn't fund wallets | the demo doesn't need wallet funding; admission is mock-friendly. For real testnet runs, fund Bob from a faucet first |

## Pulling a different Qwen model later

```bash
make ssh
ollama pull qwen2.5:3b           # smaller, faster, may struggle with codegen
# edit /etc/delftclaw/instances/<instance>.env, change QWEN_MODEL
sudo systemctl restart 'delftclaw-mcp@<instance>.service'
```

Or, to change the model for every future scenario, edit the default in
`deploy/scenario_boot.py:QWEN_MODEL` (or set the `QWEN_MODEL=` env var
when invoking `make scenario`).
