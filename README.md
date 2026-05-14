# DelftClaw

DelftClaw is the shared prototype for a **Claw Network**: a peer-to-peer
mesh of OpenClaw agents that admit each other by Bitcoin donation,
discover and download files across each other's seedboxes, and
**negotiate new IPv8 wire protocols at runtime by gossipping markdown
descriptors that get compiled into live `Community` classes by a local
LLM**.

The intended user experience is that a person talks to their OpenClaw
agent in natural language:

```text
OpenClaw: what files are stored on our Claw Network?
OpenClaw: what files are stored on our Claw Network containing "Creative Commons"?
OpenClaw: go to the Claw Network, find the Creative Commons Audio Archive 2023, and play a random file.
```

The third prompt is the canonical scenario. A consumer agent on one
node finds a file on another node's seedbox, pays a donation to be
admitted, **learns the search protocol the seedbox uses (which it had
never seen before)**, runs SEARCH, downloads the file via BitTorrent,
opens it. The architectural bet: *the protocol itself becomes content*
— markdown descriptors can be hashed, gossipped, cached, and compiled
on arrival. The network grows new protocols at the same speed it grows
new files. No software releases. Same idea as Agora
(arXiv:2410.11905) and the Agent Network Protocol (ANP).

For the canonical reference, read [`PROJECT_DESIGN.md`](PROJECT_DESIGN.md);
for the developer-facing distillation, [`docs/architecture.md`](docs/architecture.md);
for the user-intent → tool-call mappings OpenClaw consumes,
[`docs/agent_intents.md`](docs/agent_intents.md).

## Quickstart

Local tests (no VPS, no network):

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
make test                       # ~80s; expect 212 passed
python -m examples.run_two_agents
```

Live multi-tenant scenario on a VPS:

```bash
make deploy                     # one-time: rsync + setup_vps.sh
make scenario NAME=seek_cc      # start two autonomous agents
make watch    NAME=seek_cc      # follow journals until Bob exits 0
make stop     NAME=seek_cc      # teardown
```

`seek_cc` is the canonical end-to-end demo (see `deploy/scenarios/seek_cc/`).
Bob donates to Alice, fetches `content_community.md`, runs SEARCH,
downloads the magnet, exits via `torrent_progress_gte_1`. Expected
runtime: 5-10 minutes on a Hostinger KVM 2 with cold-loaded Qwen.

## Repository Layout

```text
DelftClaw/
|-- identity/                # seed -> BIP-32 -> ipv8/app/wallet keys
|-- communication/           # SeedboxCommunity bootstrap + BitTorrent
|-- protocol/                # the .md overlay system + compiler + sandbox
|   |-- schema.md            # canonical descriptor format
|   |-- compiler.py          # parse -> validate -> LLM -> AST -> exec -> test vectors
|   |-- registry.py          # OverlayRegistry: runtime IPv8 registration
|   |-- sandbox.py           # AST whitelist + namespaced safe_exec
|   |-- manifest.py          # network manifest primitive
|   `-- examples/            # echo_overlay.md, content_community.md, delftclaw_network.md
|-- admission/               # bitcoinlib-backed donation verifier
|-- agent/                   # the per-node process
|   |-- runtime.py           # OpenClawAgent (owns IPv8 + overlays + wallet + torrents)
|   |-- tools.py             # the 16 LLM-callable tools
|   |-- mcp_server.py        # production FastMCP streamable-HTTP server
|   |-- loop.py              # offline-test internal tool-call loop
|   `-- cli.py               # `python -m agent {info,mcp,run,serve}`
|-- deploy/                  # autonomous multi-tenant VPS scenarios
|   |-- scenario_boot.py     # orchestrator (manifest -> systemd units)
|   |-- watchdog.py          # per-agent polling loop
|   |-- mission.py           # zero-shot mission descriptor parser
|   |-- stop_predicates.py   # named termination predicates
|   |-- state_snapshot.py    # collect_state() for the watchdog
|   |-- systemd/             # delftclaw-mcp@.service / delftclaw-watchdog@.service
|   |-- scenarios/           # seek_cc/scenario.yaml + alice/bob mission.md
|   `-- vps/                 # setup_vps.sh + bootstrap scripts
|-- shared/                  # cross-cutting identifiers, errors, logging
|-- examples/                # run_two_agents, pull_sync_demo
|-- security/                # SubQ1/2/3 experiment scaffolding + colleague gateway
|-- redteam/                 # signed append-only log + HTTP replication
|   |-- primitives/          # SignedAppendOnlyLog, PeerLog (research artefact)
|   `-- integration/         # peer_transport.py + pull_loop.py + server.py
|-- tests/                   # in-tree pytest suite
|-- configs/                 # template.env + host.env.example
|-- agent.py                 # legacy P2PAgent (red-step TDD fixture; not the v5.1 entry point)
|-- network.py               # UDPEndpoint stub used by agent.py only
|-- Makefile                 # operator entry: deploy / scenario / watch / stop / test
|-- docs/agent_intents.md    # OpenClaw user-intent → tool-call mappings
|-- PROJECT_DESIGN.md        # canonical reference (v5.1)
|-- docs/architecture.md     # developer-facing distillation
`-- README.md                # this file
```

## Main Components

### Identity (`identity/`)

Each agent has one BIP-39 seed that derives three independent keys
through a BIP-32 chain:

```text
m/44'/0'/0'/0/0   ->  Ed25519 IPv8 transport key (LibNaCLSK)
m/44'/0'/0'/1/0   ->  Ed25519 application-layer signing key
                  ->  secp256k1 Bitcoin HD wallet (bitcoinlib does its own BIP-32)
```

The project-wide agent identifier is content-derived:

```text
agent_id = sha256(ipv8_raw_pubkey || network)
```

Seed loading is pluggable: `MnemonicSeedSource` for demos,
`KeyfileSeedSource` (default `~/.openclaw/identity/seed.txt`, auto-generates
on first run) for VPS production, `KeyringSeedSource` for OS keyring,
`EnvSeedSource` for dev. The wallet is a thin wrapper over
`bitcoinlib.wallets.Wallet`; addresses default to testnet bech32 and the
wallet CLI (`python -m identity.wallet`) exposes `address`, `balance`,
`send`.

### Communication (`communication/`)

`SeedboxCommunity` is the only statically-loaded IPv8 community — it's
the bootstrap layer everything else gossips over. Nine wire messages:

| msg_id | Name | Purpose |
|---|---|---|
| 1 | `JoinRequestPayload` | joiner ships a donation txid |
| 2 | `JoinResponsePayload` | gatekeeper accepts/rejects |
| 3 | `OverlayOfferPayload` | "I have overlay <md_hash>" |
| 4 | `OverlayRequestPayload` | "send me <md_hash>" |
| 5 | `OverlayDeliveryPayload` | the markdown bytes |
| 6-8 | `Manifest{Offer,Request,Delivery}` | network manifest gossip |
| 9 | `PeerIntroPayload` | live wallet + overlay catalogue post-admission |

`community_id = b"openclaw_seedbox_v1\x00"` is the only hand-picked
rendezvous id; every other overlay's id is `sha1(canonical_md)[:20]`.

`BitTorrentService` (`communication/bittorrent.py`) is a thin Protocol
with a `LibTorrentService` impl and a `StubBitTorrentService` fallback
for machines without libtorrent (the test suite uses the stub
unconditionally).

### Protocol Overlays (`protocol/`)

The headline contribution. A markdown file describes one IPv8
community type — its wire format, handler semantics, byte-level test
vectors. Receiving agents fetch that markdown, compile it into a
runnable `Community` subclass via an LLM, and register the result with
their live IPv8 instance at runtime.

`protocol/schema.md` is the meta-schema. Every `*_community.md` must
declare: `# Identity`, `# Messages` (with allowlisted encodings),
`# Errors`, `# Dependencies`, `# Test Vectors`. The 20-byte
`community_id` is content-derived, not hand-picked.

Compiler pipeline (`protocol/compiler.py`):

```text
md_text
  -> parse_md + schema validate (encoding allowlist, msg_id uniqueness)
  -> canonicalize -> sha1[:20] = community_id
  -> LLM completion (system prompt + parsed sections)
  -> strip code fences -> AST whitelist (`protocol/sandbox.py`)
  -> safe_exec in namespaced builtins
  -> assert generated class declares the right community_id
  -> run every (fields, bytes) test vector — fail closed on mismatch
  -> CompiledOverlay
```

Two LLM clients implement the same `LLMClient` Protocol
(`protocol/llm.py`): `OpenAICompatibleClient` for production
(Qwen on Ollama, or any OpenAI-compatible endpoint), `StubLLMClient`
keyed by `community_id` for tests + the `--compiler-stub` CLI mode.

Overlays can arrive three ways: `--publish-overlay` at boot, the
`overlay_publish` tool at runtime, or — the load-bearing path — the
network via `OVERLAY_OFFER` → `OVERLAY_REQUEST` → `OVERLAY_DELIVERY`,
verified by re-hashing the delivered bytes.

### Admission (`admission/`)

`DonationVerifier` is the gatekeeper-side check on a `JoinRequest`.
Given a claimed Bitcoin transaction id:

```python
verifier = DonationVerifier(
    seedbox_address="tb1qexample...",
    min_sats=10000,
    min_confirmations=1,
    network="testnet",
)
result = verifier.verify(txid_hex)   # DonationVerification(accepted, reason, paid_sats, confirmations)
```

`bitcoinlib.services.Service` is constructed lazily on the first
`verify()` call — eager construction probes the provider pool
synchronously over the network and was causing systemd boot timeouts.

### Agent Runtime + MCP Tools (`agent/`)

`OpenClawAgent` owns the per-node stack: IPv8 instance, bootstrap
`SeedboxCommunity`, `BitcoinWallet`, `BitTorrentService`,
`OverlayRegistry`. `await agent.start()` brings everything up; the
`DonationVerifier` is wired to the agent's own wallet address as the
seedbox.

The production path is `agent/mcp_server.py` — a FastMCP streamable-HTTP
server that exposes 16 tools to OpenClaw's chat session:

| Tool | Effect |
|---|---|
| `peers_list` / `peer_add` | enumerate / pre-introduce peers |
| `wallet_address` / `wallet_balance` / `wallet_send` | wallet ops |
| `seedbox_donate_and_join` | wallet.send → JOIN_REQUEST → await JoinResponse |
| `overlays_list` / `overlay_describe` | inspect loaded overlays + schema |
| `overlay_fetch_and_load` | request a descriptor from a peer, compile, register |
| `overlay_publish` | serve a `.md` over OVERLAY_REQUEST |
| `overlay_invoke` | generic dispatcher: send any compiled-overlay message |
| `agent_inject_manifest` | parse + cache a network manifest, pre-introduce its peers |
| `network_join` | end-to-end admission: manifest → peer_add → fetch overlays → donate → JOIN |
| `torrent_seed` / `torrent_fetch` / `torrent_stats` | libtorrent surface |

Two LLMs operate inside this picture and never overlap: OpenClaw's
chat-host LLM picks which tool to call; a local Qwen on the VPS only
runs when a new `.md` overlay first arrives and needs compiling.

### Deploy + Scenarios (`deploy/`)

`deploy/` lets two or more OpenClaw agents talk to each other on one
VPS without keyboard input. Each scenario is a YAML manifest plus one
`mission.md` per agent. `make scenario NAME=seek_cc` SSHes to the VPS,
parses the manifest, generates seed files, writes one
`/etc/delftclaw/instances/<scenario>-<agent>.env` per agent, starts a
`delftclaw-mcp@<instance>.service` and a `delftclaw-watchdog@<instance>.service`
per agent, and cross-introduces peers.

The watchdog drives `python -m openclaw agent --message <prompt>` in a
polling loop. Each tick builds a deterministic prompt from
`{mission.md, snapshot, history tail}`, runs the LLM, and writes one
JSONL line. The LLM never decides termination — stop predicates are
named functions of the snapshot (`torrent_progress_gte_1`,
`peer_count_gte_N`, `wallet_received_sats`, `never`).

## Local Configuration

`deploy/scenario_boot.py` writes per-instance env files on the VPS
itself; you don't hand-edit them. The env vars each MCP unit reads:

```env
PYTHONPATH=/opt/delftclaw
HOME=/var/lib/delftclaw/<scenario>/<agent>
SEED_FILE=$HOME/seed.txt
NETWORK=TESTNET
BTC_NETWORK=testnet
IPV8_HOST=0.0.0.0
IPV8_PORT=8190                       # per-agent in [8190, 8199]
MCP_HOST=0.0.0.0
MCP_PORT=18765                       # per-agent in [18765, 18774]
PUBLISH_OVERLAY=/opt/delftclaw/protocol/examples/content_community.md
MANIFEST_FILE=/etc/delftclaw/scenarios/<instance>/network_manifest.md
QWEN_BASE_URL=http://<gpu-host>:11434/v1
QWEN_MODEL=qwen3.6:27b
LOG_DIR=/var/log/delftclaw/scenarios/<scenario>
```

For local dev (no VPS) copy the template and tweak:

```bash
cp configs/template.env configs/yourName.local.env
```

`configs/*.local.env` is gitignored. Per-host overrides for the
compiler LLM live in `configs/host.env` (also gitignored), shape
documented in `configs/host.env.example`. Do not commit bot tokens,
wallet seeds, API keys, or private identity files.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the test suite:

```bash
make test
```

Cover protocol compile, overlay registry, content community SEARCH,
BitTorrent stub, agent runtime + MCP server, scenario manifest parser,
watchdog turn builder, stop predicates, and the redteam signed-log
suite. Expected: 212 passed (see `PROJECT_DESIGN.md §16`).

## Current Status

Working:

```text
BIP-32 multi-key identity + bitcoinlib HD wallet
SeedboxCommunity bootstrap (9 wire messages)
Markdown overlay compiler with AST sandbox + test-vector gate
OverlayRegistry: markdown path + traditional Python-class path
content_community SEARCH overlay (canonical demo)
BitTorrent service (libtorrent + stub fallback)
OpenClawAgent + 16-tool MCP surface
Donation verifier (lazy bitcoinlib.Service)
Autonomous scenario orchestrator (scenario_boot + watchdog + stop predicates)
Network manifest gossip (MANIFEST_* trio) + PEER_INTRO
Mission-descriptor parser (rejects recipes, smuggled tool names, ≥3-step lists)
JSONL turn trace per agent for replay
```

In progress / known gaps:

```text
Production sandbox upgrade (subprocess + seccomp or WASM)
Wallet-address discovery via PEER_INTRO is plumbed but UX needs polish
LLM-cache plumbing across model versions
Identity MCP + Security MCP (colleague-contributed) coexistence story
Multi-VPS scenarios (current scenarios are single-VPS)
```

Optional technical directions:

```text
Pre-compiled overlay cache shipped offline for air-gapped deployments
Cross-stack overlay interop (TypeScript/Rust agents reading the same .md)
Cryptographic proof of seedbox availability
Donation evidence compression for scaling reputation tracking
```

## More Documentation

- [`PROJECT_DESIGN.md`](PROJECT_DESIGN.md) — canonical reference (v5.1).
- [`docs/architecture.md`](docs/architecture.md) — developer-facing distillation.
- [`docs/agent_intents.md`](docs/agent_intents.md) — user-intent → MCP tool-call mappings the OpenClaw system prompt loads.
- [`deploy/README.md`](deploy/README.md) — operator runbook for `make scenario`.
- [`docs/threat_model.md`](docs/threat_model.md) — current threat enumeration.
- [`docs/sq1_research.md`](docs/sq1_research.md) + [`docs/sq1_source_map.md`](docs/sq1_source_map.md) — SubQ1 (preventative isolation) research notes.
