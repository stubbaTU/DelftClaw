# DelftClaw

DelftClaw is the research prototype for a Claw Network: autonomous
OpenClaw agents that form a peer-to-peer seedbox community, exchange
protocol overlays, retrieve Creative Commons content, and run the three
VukZero thesis security evaluations.

The current repository is intentionally scoped to:

- `seek_cc`, the canonical OpenClaw scenario.
- SQ1, tool-level prevention with AgentDojo and VukZero capability checks.
- SQ2, accountability and reputation-lag evaluation.
- SQ3, system-level containment with gVisor, egress filtering, and hardened
  resource proxies.

## Quickstart

Local development:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest
python -m examples.run_two_agents
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pytest
```

VPS scenario flow:

```bash
make deploy
make scenario NAME=seek_cc
make watch NAME=seek_cc
make trace NAME=seek_cc
make stop NAME=seek_cc
```

## Repository Layout

```text
DelftClaw/
|-- agent/                  # OpenClawAgent runtime, MCP server, CLI, LLM tool loop
|-- admission/              # bitcoinlib donation verifier
|-- communication/          # SeedboxCommunity bootstrap overlay + BitTorrent service
|-- configs/                # host.env example for per-machine deployment settings
|-- deploy/                 # VPS bootstrap and seek_cc scenario runner
|   |-- scenarios/seek_cc/  # canonical OpenClaw scenario
|   |-- systemd/            # templated MCP/watchdog/identity/security units
|   `-- vps/                # host setup and seek_cc helper script
|-- docs/                   # architecture, agent intents, threat model, research notes
|-- examples/               # local two-agent and signed-log pull demos
|-- identity/               # seed loading, BIP-derived keys, wallet wrapper
|-- protocol/               # markdown overlay schema, compiler, sandbox, registry
|-- redteam/                # signed append-only logs + HTTP pull replication
|-- replication/            # seedbox/deployment provisioning experiments
|-- scripts/                # operational helper scripts
|-- security/               # SQ1, SQ2, SQ3 security evaluation code
|-- shared/                 # identifiers, credentials, logging, CSV helpers
|-- tests/                  # pytest suite
|-- Makefile                # deploy/scenario/watch/trace/test operator entrypoint
`-- README.md
```

## Core Components

### Agent Runtime

`agent/runtime.py` owns a node's IPv8 process, bootstrap
`SeedboxCommunity`, wallet, BitTorrent service, overlay registry,
community signed log, peer-log pull loop, and optional network manifest.

`python -m agent` exposes:

- `info` for identity, pubkey, wallet address, and peer-introduction lines.
- `mcp` for production FastMCP streamable-HTTP serving.
- `run` and `serve` for local/offline tool-loop development.

### MCP Tool Surface

`agent/tools.py` builds the LLM-facing tools. The active surface covers peer
introduction, wallet inspection, signed-log community admission, seedbox
purchase/provisioning entries, overlay publish/fetch/describe/list/invoke,
network manifest injection, torrent seed/fetch/stats, and the
`content_search_and_fetch` helper used by `seek_cc`.

### Bootstrap Communication

`communication/community.py` defines `SeedboxCommunity`, the static IPv8
community used to exchange peer introductions, overlay descriptors,
manifests, and signed-log join messages.

### Runtime Protocol Overlays

`protocol/schema.md` defines the markdown descriptor format for dynamic
communities. `protocol/compiler.py` parses, validates, asks an
OpenAI-compatible model for Python source, checks the AST sandbox, executes in
a restricted namespace, and runs message test vectors before activation.

### Deployment

`deploy/scenario_boot.py` parses `deploy/scenarios/seek_cc/scenario.yaml`,
creates per-agent state, writes systemd env files, starts one MCP unit and
one watchdog unit per agent, cross-introduces peers, and wires peer-log pull
URLs when configured.

The watchdog builds each turn from the mission, a deterministic state
snapshot, and recent history. Stop conditions live in
`deploy/stop_predicates.py`.

## Security Evaluations

`security/` contains only the active thesis security code:

- `security/preventative_layer/`: SQ1 AgentDojo prevention experiments.
- `security/accountability_layer/`: SQ2 signed-log accountability and
  reputation-lag experiments.
- `security/containment_layer/`: SQ3 containment-boundary experiments with
  mock protected resources, hardened proxies, gVisor/runsc, iptables egress
  checks, deterministic probes, and paper-ready exports.
- `security/preventative_layer/permissions/`: shared permission primitives used by SQ1 and the
  OpenClaw tool broker.

## Configuration

Copy host-specific deployment settings from the example:

```bash
cp configs/host.env.example configs/host.env
```

`configs/host.env` is gitignored and answers "where am I running?":
Tailscale/GPU endpoint, `QWEN_BASE_URL`, `QWEN_MODEL`, and `BTC_NETWORK`.

Do not commit wallet seeds, private keys, bot tokens, API keys, or
machine-specific host overrides.

## Useful Commands

```bash
make test                       # curated local pytest target
python -m pytest                # full local pytest suite
python -m examples.run_two_agents
python -m examples.pull_sync_demo

make deploy                     # rsync + VPS bootstrap
make scenario NAME=seek_cc      # start scenario
make scenarios                  # list active systemd units
make watch NAME=seek_cc         # full journal tail
make watch-ipv8 NAME=seek_cc    # filtered IPv8/tool/error tail
make trace NAME=seek_cc         # one-shot per-agent snapshot
make stop NAME=seek_cc          # teardown scenario

make sq3-containment-preflight
make sq3-containment-official
```

## Current Status

Working in-tree:

- BIP-derived identity and wallet wrapper;
- static IPv8 bootstrap community;
- markdown overlay compiler, sandbox, registry, and content-search overlay;
- FastMCP server and LLM tool loop;
- BitTorrent service with stub fallback;
- signed-log community replay for admission, treasury, and seedbox growth;
- redteam signed-log HTTP replication;
- strict `seek_cc` scenario parser, mission parser, watchdog, traces, and
  systemd deployment;
- SQ1/SQ2/SQ3 VukZero security evaluation infrastructure.

Known gaps:

- generated overlay code still runs in-process after AST filtering;
  production isolation should move to a stronger subprocess, seccomp, or
  WASM boundary;
- cloud seedbox spawning is represented by mock/provisioning entries, with
  provisioning experiments living in `replication/`;
- multi-VPS operation is not the default path; current scenarios are
  primarily single-VPS multi-agent deployments.

## More Documentation

- `docs/architecture.md` — as-built architecture and design rationale.
- `docs/agent_intents.md` — user-intent to tool-call mappings.
- `deploy/README.md` — VPS and scenario operator runbook.
- `configs/README.md` — host configuration.
- `security/README.md` — active security package scope.
- `docs/threat_model.md` — threat enumeration.
- `docs/sq1_research.md` and `docs/sq1_source_map.md` — SQ1 notes.
