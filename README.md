# DelftClaw

DelftClaw is the research prototype for a Claw Network: autonomous
OpenClaw agents that form a peer-to-peer seedbox community, admit new
members through donation evidence, exchange file indexes, retrieve
content through BitTorrent, and grow their infrastructure when the
community state says more seedboxes are needed.

The project has three main ideas:

- **Protocol is content.** IPv8 overlays can be described as markdown,
  gossiped over the bootstrap community, compiled by a local
  OpenAI-compatible model, checked against byte-level test vectors, and
  registered into a live IPv8 process without a software release.
- **Community state is replayed from signed logs.** The current
  admission and treasury path is no-treasurer: agents append signed
  `donation_intent`, `seedbox_purchase_intent`, and
  `seedbox_provisioned` entries. Peers replicate logs and replay the
  same rules to derive membership, treasury balance, and seedbox count.
- **Security experiments sit beside the network.** The repo includes
  preventative, accountability, and impact-containment layers used by
  the paper/demo flows: gateway policy, signed evidence, reputation,
  log integrity, gVisor/iptables artifacts, and defended tool execution.

The canonical user story is still simple: one agent joins a Claw
community, learns the content-search protocol from another agent,
searches for Creative Commons content, fetches the returned magnet, and
exits when the download completes. The fuller demo adds additional
agents, donation-based admission, seedbox-growth accounting, and the
security checklist.

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

Community-demo flow:

```bash
python -m deploy.community_demo --provider mock --root community_demo_state --reset
make community-demo
make community-demo-real
make community-demo-stop
```

`seek_cc` is the compact end-to-end scenario. `community_demo` is the
four-agent paper-demo scenario: agent 1 founds and seeds content, agents
2 and 3 donate to join, agent 2 searches and retrieves, and agent 4
joins and records the mock second seedbox once the capacity threshold is
active.

## Repository Layout

```text
DelftClaw/
|-- agent/                  # OpenClawAgent runtime, MCP server, CLI, LLM tool loop
|-- admission/              # legacy bitcoinlib donation verifier
|-- claw_community/         # direct community model/service used by the checklist demo
|-- communication/          # SeedboxCommunity bootstrap overlay + BitTorrent service
|-- configs/                # host.env example + experiment template.env
|-- deploy/                 # VPS bootstrap, scenario runner, watchdog, demos
|   |-- scenarios/          # seek_cc, community_demo, secure_community_demo, security_layers
|   |-- systemd/            # templated MCP/watchdog/identity/security units
|   `-- vps/                # host setup and security/identity bootstrap scripts
|-- docs/                   # architecture, agent intents, threat model, research notes
|-- examples/               # local two-agent and signed-log pull demos
|-- identity/               # seed loading, BIP-derived keys, wallet wrapper
|-- protocol/               # markdown overlay schema, compiler, sandbox, registry
|-- redteam/                # signed append-only logs + HTTP pull replication
|-- replication/            # seedbox/deployment provisioning experiments
|-- scripts/                # operational helper scripts
|-- security/               # SQ1/SQ2/SQ3 security infrastructure and MCP integration
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

- `info` for identity, pubkey, wallet address, and peer-introduction
  lines.
- `mcp` for production FastMCP streamable-HTTP serving.
- `run` and `serve` for local/offline tool-loop development.

Important boot flags include `--publish-overlay`, `--register-community`,
`--peer`, `--manifest`, `--genesis`, `--initial-balance-sats`,
`--peer-log-url`, and `--compiler-stub`.

### MCP Tool Surface

`agent/tools.py` builds the LLM-facing tools. The current surface covers:

- peer introduction and listing;
- wallet address, balance, and sends;
- legacy seedbox donate/join;
- no-treasurer community admission, member count, treasury balance, and
  recent signed-log entries;
- seedbox purchase/provisioning entries;
- overlay publish, fetch, describe, list, and generic invocation;
- network manifest injection and join;
- torrent seed, fetch, stats;
- `content_search_and_fetch`, the paper-demo helper that sends
  `SEARCH_REQUEST`, reads `content_community` responses, and fetches the
  first returned magnet.

OpenClaw's chat model chooses these tools. The local compiler model is
only used when a new markdown overlay must become runnable Python.

### Bootstrap Communication

`communication/community.py` defines `SeedboxCommunity`, the only static
IPv8 community. It handles 11 wire messages:

| IDs | Purpose |
|---|---|
| 1-2 | legacy Bitcoin txid join request/response |
| 3-5 | overlay offer/request/delivery |
| 6-8 | network manifest offer/request/delivery |
| 9 | peer intro with wallet address and known overlay ids |
| 10-11 | signed-log community join request/response |

Markdown overlays and manifests are addressed by `sha1(canonical_text)[:20]`.
Deliveries are rehashed before use, and individual descriptors are capped
at 64 KiB.

### Runtime Protocol Overlays

`protocol/schema.md` defines the descriptor format for markdown
communities. `protocol/compiler.py` parses, validates, canonicalizes,
asks an OpenAI-compatible LLM for Python source, strips fences, checks
the AST sandbox, executes in a restricted namespace, and runs every
message test vector before activation.

`protocol/registry.py` supports two paths:

- markdown descriptors that can be exchanged over the network;
- local hand-written Python `Community` classes via
  `--register-community`, useful for static colleague experiments.

The canonical demo overlay is
`protocol/examples/content_community.md`.

### Community State

`agent/community_state.py`, `redteam/`, and the community tools provide
the no-treasurer path. Agents append signed local entries, serve them
over a redteam FastAPI endpoint when configured, pull peers' logs, and
replay the merged entries. Replay derives:

- admitted members;
- treasury balance;
- accepted donations;
- pending and provisioned seedbox purchases;
- whether the seedbox-growth threshold is active.

The legacy on-chain verifier remains in `admission/` and is still used
by the old `seedbox_donate_and_join` path.

### Deployment And Scenarios

`deploy/scenario_boot.py` parses `deploy/scenarios/<name>/scenario.yaml`,
creates per-agent state, writes systemd env files, starts one MCP unit
and one watchdog unit per agent, cross-introduces peers, and wires
peer-log pull URLs when `redteam_port` is present.

The watchdog builds each turn from the mission, a deterministic state
snapshot, and recent history. Stop conditions are code predicates in
`deploy/stop_predicates.py`, not LLM decisions. Current predicate
families include torrent completion, peer count, wallet delta,
community member count, community seedbox count, and security-layer
completion.

Use `deploy/README.md` for the operator runbook.

### Security Infrastructure

`security/` contains the research security layers:

- SQ1 preventative gateway and Brain/Hands permission checks;
- SQ2 accountability, reputation, seedbox evidence, and microtask
  experiments;
- SQ3 impact containment, sandbox readiness, protected-path artifacts,
  and integrity tests;
- security MCP integration under `security/integration/`.

The direct checklist runner `python -m deploy.community_demo` exercises
community state, signed audit logs, CSV-backed file catalogs, defended
gateway behavior, reputation/expulsion, and tamper detection on local
or mock infrastructure.

## Configuration

Copy host-specific deployment settings from the example:

```bash
cp configs/host.env.example configs/host.env
```

`configs/host.env` is gitignored and answers "where am I running?":
Tailscale/GPU endpoint, `QWEN_BASE_URL`, `QWEN_MODEL`, and
`BTC_NETWORK`.

`configs/template.env` is tracked and answers "what experiment am I
running?": gateway mode, ban threshold, run id, security conditions, and
log paths. Copies named `*.local.env` are ignored.

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

python -m deploy.community_demo --provider mock --root community_demo_state --reset
make community-demo
make community-demo-real
make community-demo-stop
```

## Current Status

Working in-tree:

- BIP-derived identity and wallet wrapper;
- static IPv8 bootstrap community;
- markdown overlay compiler, sandbox, registry, and content-search
  overlay;
- local Python-community registration;
- FastMCP server and LLM tool loop;
- BitTorrent service with stub fallback;
- signed-log community replay for admission, treasury, and seedbox
  growth;
- redteam signed-log HTTP replication;
- strict scenario parser, mission parser, watchdog, traces, and systemd
  deployment;
- direct and real-agent community demos;
- security gateway, accountability, and integrity experiment scaffolding.

Known gaps and active edges:

- generated overlay code still runs in-process after AST filtering;
  production isolation should move to a stronger subprocess, seccomp, or
  WASM boundary;
- cloud seedbox spawning is represented by mock/provisioning entries in
  the real-agent demo, with provisioning experiments living in
  `replication/` and security modules;
- multi-VPS operation is not the default path; current scenarios are
  primarily single-VPS multi-agent deployments;
- live Bitcoin/testnet admission is preserved but the main demo path
  uses synthetic balances and signed-log replay.

## More Documentation

- `docs/architecture.md` — as-built architecture and design rationale.
- `docs/agent_intents.md` — user-intent to tool-call mappings.
- `deploy/README.md` — VPS and scenario operator runbook.
- `configs/README.md` — configuration file split.
- `security/README.md` — security package scope.
- `docs/threat_model.md` — threat enumeration.
- `docs/sq1_research.md` and `docs/sq1_source_map.md` — SQ1 notes.
