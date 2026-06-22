# DelftClaw

DelftClaw is the research prototype for a Claw Network: autonomous
OpenClaw agents that form a peer-to-peer seedbox community, admit new
members through donation evidence, and exchange file indexes and content
over IPv8.

The project has two main ideas:

- **Protocol is content.** IPv8 overlays can be described as markdown,
  gossiped over the bootstrap community, compiled by a local
  OpenAI-compatible model, checked against byte-level test vectors, and
  registered into a live IPv8 process without a software release.
- **Community state is replayed from signed logs.** The admission and
  treasury path is no-treasurer and has no gatekeeper key: agents append
  signed `donation_intent` entries; peers replicate every log and replay
  the same rules to derive membership and treasury balance, all
  converging on the same view.

The bundled scenarios exercise these: `payment` shows keyless,
replay-decided membership followed by payments over a markdown overlay;
`file_share` and `file_transfer` show wire-distributed
markdown-as-overlay protocols.

## Quickstart

Local development:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest
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
make scenario NAME=payment
make watch NAME=payment
make trace NAME=payment
make stop NAME=payment
```

The bundled scenarios are `payment` (three agents: alice founds the
community, bob and charlie donate to join — membership decided by every
peer replaying the signed donation logs, no gatekeeper — then ask for and
receive fake BTC over a markdown-as-overlay, with the signed log as the
money ledger; bob authors a receipt protocol and charlie evolves it),
`file_share`, and `file_transfer` (both demonstrate wire-distributed
markdown-as-overlay protocols).

## Repository Layout

```text
DelftClaw/
|-- agent/                  # OpenClawAgent runtime, MCP server, CLI, LLM tool loop
|-- communication/          # SeedboxCommunity bootstrap overlay + BitTorrent service
|-- configs/                # .env.example — per-host LLM config (endpoint, model, key)
|-- deploy/                 # VPS bootstrap, scenario runner, watchdog
|   |-- scenarios/          # payment, file_share, file_transfer
|   `-- systemd/            # templated MCP / watchdog / llm-proxy units
|-- identity/               # seeds, BIP keys, wallet, typed ids, logging config
|-- protocol/               # markdown overlay schema, compiler, sandbox, registry
|-- signed_log/             # signed append-only logs + HTTP pull replication
|-- scripts/                # operational helper scripts (llm proxy, mcp probe)
|-- experiments/            # SQ3 behavioural-reproduction + convergence harness
|-- results/                # SQ3 behavioural-reproduction run outputs
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
`--peer`, `--manifest`, `--genesis`, `--initial-balance-sats`, and
`--peer-log-url`.

### MCP Tool Surface

`agent/tools.py` builds the LLM-facing tools. The current surface covers:

- peer introduction and listing (`peers_list`, `peer_add`);
- wallet address, balance, and sends (`wallet_address`,
  `wallet_balance`, `wallet_send`);
- no-treasurer community admission via donation, join via a peer, member
  count, treasury balance, and recent signed-log entries
  (`community_donate_and_join`, `community_join_via_peer`,
  `community_member_count`, `community_treasury_balance`,
  `community_log_list_recent`);
- payment request and send over the payment overlay (`request_payment`,
  `send_payment`);
- overlay publish, fetch/load, describe, list, generic invocation, and
  LLM authoring (`overlay_publish`, `overlay_fetch_and_load`,
  `overlay_describe`, `overlays_list`, `overlay_invoke`,
  `overlay_author_and_publish`);
- network manifest injection (`agent_inject_manifest`);
- torrent seed, fetch, stats (`torrent_seed`, `torrent_fetch`,
  `torrent_stats`);
- `content_search_and_fetch` and `content_fetch_via_transfer`, the
  file_share/file_transfer demo helpers that send a search request, read
  `content_community` responses, and fetch the returned content.

OpenClaw's chat model chooses these tools. The local compiler model is
only used when a new markdown overlay must become runnable Python.

### Bootstrap Communication

`communication/community.py` defines `SeedboxCommunity`, the only static
IPv8 community. It handles eight wire messages:

| IDs | Purpose |
|---|---|
| 3-5 | overlay offer/request/delivery |
| 9 | peer intro with wallet address and known overlay ids |
| 10-11 | signed-log community join request/response |
| 12-13 | content request/delivery |

Markdown overlays are addressed by `sha1(canonical_text)[:20]`.
Deliveries are rehashed before use, and both overlay descriptors and
content payloads are capped at 64 KiB.

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

`agent/community_state.py`, `signed_log/`, and the community tools provide
the no-treasurer path. Agents append signed local entries, serve them
over a signed_log FastAPI endpoint when configured, pull peers' logs, and
replay the merged entries. Replay derives:

- admitted members;
- treasury balance;
- accepted donations.

There is no gatekeeper key: every peer converges on the same membership
view by replaying the same signed logs.

### Deployment And Scenarios

`deploy/scenario_boot.py` parses `deploy/scenarios/<name>/scenario.yaml`,
creates per-agent state, writes systemd env files, starts one MCP unit
and one watchdog unit per agent, cross-introduces peers, and wires
peer-log pull URLs when `signed_log_port` is present.

The watchdog builds each turn from the mission, a deterministic state
snapshot, and recent history. Stop conditions are code predicates in
`deploy/stop_predicates.py`, not LLM decisions. Current predicate
families include torrent completion, peer count, wallet delta, and
community member count.

Run `make help` for the operator command reference.

## Configuration

Copy the LLM config from the example and fill it in:

```bash
cp configs/.env.example configs/.env
```

`configs/.env` is gitignored (it holds the real API key) and supplies the
LLM endpoint, model, key, provider, and the local proxy's port/upstream
(`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`, `LLM_API_PROVIDER`,
`LLM_PROXY_PORT`, `LLM_PROXY_UPSTREAM`). Every variable is **required** —
boot fails loud if any is missing.

Do not commit wallet seeds, private keys, bot tokens, API keys, or
machine-specific host overrides.

## Useful Commands

```bash
make test                       # curated local pytest target
python -m pytest                # full local pytest suite

make deploy                     # rsync + VPS bootstrap
make scenario NAME=payment      # start scenario
make scenarios                  # list active systemd units
make watch NAME=payment         # full journal tail
make watch-ipv8 NAME=payment    # filtered IPv8/tool/error tail
make trace NAME=payment         # one-shot per-agent snapshot
make stop NAME=payment          # teardown scenario
```

## Current Status

Working in-tree:

- BIP-derived identity and wallet wrapper;
- static IPv8 bootstrap community;
- markdown overlay compiler, sandbox, registry, LLM authoring, and
  content-search overlay;
- local Python-community registration;
- FastMCP server and LLM tool loop;
- BitTorrent service with stub fallback;
- signed-log community replay for admission, treasury, and payments;
- signed_log signed-log HTTP replication;
- strict scenario parser, mission parser, watchdog, traces, and systemd
  deployment;
- scenario-driven multi-agent demos (`payment`, `file_share`,
  `file_transfer`);
- the SQ3 cross-compilation behavioural-reproduction and convergence
  harness in `experiments/`.

Known gaps and active edges:

- generated overlay code still runs in-process after AST filtering;
  production isolation should move to a stronger subprocess, seccomp, or
  WASM boundary;
- cloud seedbox spawning is represented by mock/provisioning entries in
  the signed log rather than real provisioning;
- multi-VPS operation is not the default path; current scenarios are
  primarily single-VPS multi-agent deployments;
- live Bitcoin/testnet admission is preserved but the main demo path
  uses synthetic balances and signed-log replay.

## More Documentation

- `experiments/README.md` — SQ3 cross-compilation behavioural-reproduction
  and convergence harness, arms, and metrics.
- `make help` — VPS deploy and scenario operator commands.
