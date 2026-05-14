# DelftClaw — Operator runbook

Target: **Hostinger KVM 2** (Ubuntu 24.04, 8 GB RAM, 2 vCPU).

**Compiler LLM (v5.1 canonical):** external GPU host reached over
Tailscale CGNAT — `QWEN_BASE_URL=http://100.73.168.12:11434/v1`,
`QWEN_MODEL=qwen3.6:27b`. The VPS itself does **not** run the model;
the local Ollama installed by `setup_vps.sh` is a dev/CI fallback only.

**Reasoning LLM:** whatever OpenClaw's chat session uses. The watchdog
drives it as a subprocess (`openclaw agent --message …`).

## TL;DR — first deploy

```bash
# On your laptop, from the repo root:
make deploy
```

That rsyncs the repo, installs system packages, Tailscale, the
`openclaw` npm CLI, a fallback local Ollama, the venv, the templated
systemd units, and the firewall rules. Idempotent; re-running is safe.

After it finishes there is **no agent running**. Agents are launched
per scenario:

```bash
make scenario NAME=seek_cc      # launch the seek_cc scenario
make watch    NAME=seek_cc      # tail every agent's journal
make stop     NAME=seek_cc      # stop and teardown
make scenarios                  # list active scenarios
python -m deploy.paper_demo --provider mock --reset
                                # run the full Paper - Demo.txt checklist locally
make paper-demo                  # run that checklist on the VPS
make paper-demo-real             # launch the real OpenClaw-agent paper demo scenario
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
| `make paper-demo` | `python -m deploy.paper_demo --provider mock --root /var/lib/delftclaw/paper_demo --reset` |
| `make paper-demo-real` | `python -m deploy.paper_demo --real-agents` |
| `make paper-demo-stop` | `python -m deploy.paper_demo --stop-real-agents` |
| `make ssh` | Open an interactive shell on the VPS |
| `make test` | Run the project pytest suite locally |

## Paper demo checklist

`deploy.paper_demo` is the single-command version of `Paper - Demo.txt`.
It uses mock/local infrastructure but exercises the real project
subsystems: community state, seedbox providers, signed community audit
log, CSV file catalog, defended gateway, reputation/expulsion, and log
integrity checks.

```bash
python -m deploy.paper_demo --provider mock --root paper_demo_state --reset
```

On the VPS, the helper exposes the same path:

```bash
make paper-demo
bash deploy/vps/demo_seek_cc.sh paper-demo
```

The command exits non-zero if any checklist item fails and prints a JSON
report with the generated goal files, signed logs, catalog, security
evidence, and integrity/tamper results.

For the actual OpenClaw-agent deployment, use the `paper_demo` scenario:

```bash
make paper-demo-real
make watch NAME=paper_demo
```

This starts four real templated MCP/watchdog pairs from
`deploy/scenarios/paper_demo`: `agent_1` founds and seeds content,
`agent_2` joins/searches/retrieves, `agent_3` joins as the third
member, and `agent_4` joins and records the mock second seedbox after
the threshold is active. Stop it with:

```bash
make paper-demo-stop
```

Override `VPS_HOST` / `VPS_USER` / `VPS_ROOT` on the command line:

```bash
make scenario VPS_HOST=other.example.com NAME=seek_cc
```

## Templated systemd units installed

`setup_vps.sh` installs four templated units under
`/etc/systemd/system/`:

| Unit | What it runs |
|---|---|
| `delftclaw-mcp@<instance>.service` | the agent's FastMCP server for one scenario instance (e.g. `seek_cc-alice`) |
| `delftclaw-watchdog@<instance>.service` | the autonomous tick driver paired with the matching mcp unit |
| `delftclaw-identity-mcp@<instance>.service` | colleague's identity MCP (BIP-44 wallet, MLS, verification tools) |
| `delftclaw-security-mcp@<instance>.service` | colleague's security MCP (gateway evidence, agentic-command surface) |

All four read their per-instance env file from
`/etc/delftclaw/instances/<instance>.env`. `make scenario NAME=…`
writes that env file for the scenario-runner pair; the
identity / security pair is written by
`deploy/vps/bootstrap_security_identity.sh` (see
`deploy/vps/README.md`).

The colleagues' non-templated gateway + seedbox-audit units are
installed separately by `deploy/vps/install_security_identity_services.sh`
and are independent of the four templated MCPs.

## Per-host overrides (`configs/host.env`)

Every developer copies `configs/host.env.example` to
`configs/host.env` (gitignored) and edits ONLY the variables that
differ on their machine: Tailscale GPU IP, `QWEN_BASE_URL` /
`QWEN_MODEL`, `BTC_NETWORK`. Both `scenario_boot.py` and
`bootstrap_security_identity.sh` read this file at boot; explicit
process env vars on the make/bash invocation still win for one-off
overrides.

`configs/template.env` (also tracked) is a DIFFERENT file — it holds
experiment knobs (gateway mode, ban threshold, run id) the colleagues'
gateway code reads. See `configs/README.md` for the split.

## Hand-written Python Community overlays (optional)

Colleagues running static / complex protocol experiments can register
a hand-written `Community` subclass directly with the agent's
`OverlayRegistry` — no markdown descriptor, no LLM compile:

```bash
python -m agent ... \
    --register-community protocol.examples.echo_traditional:EchoTraditionalCommunity \
    mcp --mcp-port 18765
```

The class must declare its own 20-byte `community_id` and ship its
`@vp_compile`-decorated `VariablePayload` subclasses in the same
module. **Local-only** — these overlays don't flow over the
bootstrap community's `OVERLAY_*` / `MANIFEST_*` messages because
Python bytecode has no canonical transmittable form. The
`overlays_list` tool exposes them with `origin: "python_class"` so
the reasoning LLM can distinguish them from markdown-derived overlays.

## Pointing the agents at a different LLM endpoint

`scenario_boot.py` reads `QWEN_BASE_URL` and `QWEN_MODEL` from its
environment and bakes them into each agent's instance env file. So:

```bash
# Production default (external GPU box via Tailscale) — no override needed:
make scenario NAME=seek_cc

# Local-Ollama fallback (e.g. if Tailscale is down):
QWEN_BASE_URL=http://127.0.0.1:11434/v1 \
QWEN_MODEL=qwen2.5-coder:7b \
make scenario NAME=seek_cc

# Some other external endpoint (vLLM, TGI, llama.cpp, ...):
QWEN_BASE_URL=https://my-vllm:8000/v1 \
QWEN_MODEL=qwen3.6:27b \
make scenario NAME=seek_cc
```

To make the change permanent for every future scenario, edit
`deploy/scenario_boot.py:QWEN_BASE_URL` / `QWEN_MODEL`. To change the
endpoint of an already-running agent, edit
`/etc/delftclaw/instances/<instance>.env` on the VPS and
`systemctl restart 'delftclaw-mcp@<instance>.service'`.

## What `setup_vps.sh` does

One-shot, idempotent, runs as root. Walks through:

1. **apt** — python3-venv, libsodium-dev, build-essential, ufw, jq, git.
2. **Tailscale** — installs the daemon and enables it. Halts with
   instructions if the VPS is not yet on a tailnet
   (`tailscale up` is interactive; rerun the script afterwards).
3. **Ollama install + model pull** — the *fallback* compiler-LLM. Only
   used when `QWEN_BASE_URL` is unset.
4. **openclaw CLI** — `npm install -g openclaw`; required because the
   watchdog drives `openclaw agent` as a subprocess.
5. **User + dirs** — creates `delftclaw` system user,
   `/var/lib/delftclaw/`, `/var/log/delftclaw/`,
   `/etc/delftclaw/{instances,scenarios}/`.
6. **venv** — `python3 -m venv` + `pip install -r requirements.txt`.
7. **systemd templates** — installs `delftclaw-mcp@.service` and
   `delftclaw-watchdog@.service`; removes any legacy non-templated unit.
8. **ufw rules** — adds rules for `22/tcp`, `8190-8199/udp`,
   `18765-18774/tcp`. Does **not** enable the firewall.

The single-instance start is gone. Use `make scenario NAME=…` instead.

## How scenarios work

A scenario is a directory under `deploy/scenarios/<name>/`:

```
deploy/scenarios/seek_cc/
├── scenario.yaml         # agents, ports, watchdog policy, peers
├── alice/
│   └── mission.md        # v5.1 zero-shot intent: Identity / Intent / Budget / Stop
└── bob/
    └── mission.md
```

The mission descriptor is strict — the parser refuses missions that
embed a recipe (backtick-quoted tool names, ≥3-step lists under
`# Intent`). See `deploy/mission_schema.md` for the rules.

`make scenario NAME=seek_cc` runs `python -m deploy.scenario_boot
seek_cc` on the VPS:

1. Parses the manifest (strict schema; see `docs/architecture.md` §13).
2. Creates `/var/lib/delftclaw/<scenario>/<agent>/` per agent.
3. Generates a deterministic BIP-39 seed file if missing.
4. Writes per-instance env files under `/etc/delftclaw/instances/`,
   each carrying `QWEN_BASE_URL` + `QWEN_MODEL` + the per-agent ports.
5. Stages the scenario tree (incl. each `mission.md`) under
   `/etc/delftclaw/scenarios/<instance>/`.
6. `systemctl enable --now delftclaw-mcp@<instance>` per agent.
7. Waits for each MCP port to come up.
8. Cross-introduces peers via the `peer_add` MCP tool.
9. `systemctl enable --now delftclaw-watchdog@<instance>` per agent.

The watchdog polls every `interval_s` seconds, builds a turn prompt
(`mission_text + state snapshot + history tail`), subprocesses
`openclaw agent --agent <instance> --message <prompt> --json`, logs
the result to `/var/log/delftclaw/scenarios/<scenario>/<agent>.jsonl`,
and exits when the stop predicate fires.

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

You should see (with `qwen3.6:27b` on the supervisor's GPU host;
timings approximate):

```
T+00s   scenario_boot wrote /etc/delftclaw/instances/seek_cc-{alice,bob}.env
T+02s   delftclaw-mcp@seek_cc-alice.service: Started
T+02s   delftclaw-mcp@seek_cc-bob.service:   Started
T+04s   bob.peer_add(alice) OK
T+30s   bob.watchdog turn=1: invokes openclaw agent (first turn ~30-90s)
T+90s   bob.watchdog turn=2: state shows admitted=true
...
T+360s  bob.watchdog: stop_predicate_satisfied; exit 0
```

If a watchdog exits non-zero, `make watch` shows the reason; the JSONL
log under `/var/log/delftclaw/scenarios/<name>/<agent>.jsonl` has the
full turn-by-turn trace.

## OpenClaw chat (interactive, optional)

The MCP servers are also reachable from an OpenClaw chat for
hand-driven debugging. The URL is per-agent:

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

The 16 tools (v5.1: `peers_list`, `peer_add`, `wallet_address`,
`wallet_balance`, `wallet_send`, `seedbox_donate_and_join`,
`overlays_list`, `overlay_describe`, `overlay_fetch_and_load`,
`overlay_publish`, `overlay_invoke`, `agent_inject_manifest`,
`network_join`, `torrent_seed`, `torrent_fetch`, `torrent_stats`)
become available to the OpenClaw LLM.

## Ports

| Port range | Proto | Direction | Why |
|---|---|---|---|
| 22 | tcp | inbound | SSH |
| 8190-8199 | udp | inbound | IPv8 peer-to-peer (one per agent) |
| 18765-18774 | tcp | inbound | FastMCP streamable-HTTP (one per agent) |
| 11434 | tcp | localhost only | Ollama fallback (do not expose externally) |
| 41641 | udp | outbound | Tailscale (production LLM path) |

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
| Watchdog turn 1 hangs ~30s then times out | Tailscale not connected, can't reach the GPU host | `make ssh; tailscale status` — should show `100.x.x.x`. If not: `tailscale up`. |
| `Connection refused` to Ollama port on GPU host | The remote Ollama is down | `curl http://100.73.168.12:11434/api/tags` from the VPS. As fallback: `QWEN_BASE_URL=http://127.0.0.1:11434/v1 make scenario NAME=…` |
| `model not found` from Ollama | `QWEN_MODEL` doesn't match a pulled tag on the endpoint | check `ollama list` on the host serving the endpoint |
| Watchdog exits with code 3 | N consecutive `openclaw agent` failures | inspect last turn in the JSONL; check Qwen endpoint health |
| `ProtocolCompileError: test vector encode mismatch` | The compiler LLM produced wire-incompatible code for a new `.md` | tighten `protocol/compiler.py:SYSTEM_PROMPT`, or pre-load via stub source |
| `ScenarioError: ... persona_file ... removed in v5.1` | Scenario YAML still uses pre-v5.1 keys | replace `persona_file:` + `goal_file:` with a single `mission_file:` per agent; see `deploy/mission_schema.md` |
| Bob's wallet shows 0 sats indefinitely | scenario doesn't fund wallets | the demo's stub verifier accepts any txid. For real testnet runs, fund Bob via a faucet first (`python -m identity.wallet --seed-file /var/lib/delftclaw/seek_cc/bob/seed.txt address`) |

## Pulling a different model later

For the supervisor's GPU host: `ollama pull <tag>` on the GPU box,
then set `QWEN_MODEL=<tag>` for future `make scenario` invocations
(or edit `deploy/scenario_boot.py:QWEN_MODEL`).

For the on-VPS fallback Ollama:

```bash
make ssh
ollama pull qwen2.5:3b           # smaller, faster, may struggle with codegen
# edit /etc/delftclaw/instances/<instance>.env, change QWEN_MODEL
sudo systemctl restart 'delftclaw-mcp@<instance>.service'
```
