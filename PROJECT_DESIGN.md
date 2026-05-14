# DelftClaw — Project Design Document

**Author:** Nikola Emilov
**Project:** CSE3000 Research Project, TU Delft, Q4 2026
**Sub-project:** Communication (integrated channel for autonomous LLM agents)
**Document version:** 5.1 — network manifests + zero-shot mission descriptors
**Last updated:** 2026-05-13

> v5.1 delta from v5.0 is summarised in §22 at the bottom of this
> document. Sections marked `v5.1:` inline call out where the
> implementation moved.

---

## Document status

This is the **binding architectural reference** for the DelftClaw codebase as
it stands today. It replaces the v4.0 trustroom + stake design, which was
withdrawn on **2026-05-08** with the supervisor's consent (see §3,
*"History of the design"*).

The companion file [`docs/architecture.md`](docs/architecture.md) is a
shorter, developer-facing distillation of the same architecture. Where the
two disagree, **this document is canonical**.

The document is organised so a reader can skim the first three sections to
understand the project context and the architectural pivot, then drill into
component-level detail from §4 onward.

---

## Table of contents

1. Purpose & research question
2. Decisions locked in
3. History of the design
4. Architectural overview
5. `identity/` — seed, BIP-32 derivation, wallets
6. `communication/` — bootstrap layer + BitTorrent
7. `protocol/` — markdown overlays + compiler
8. `admission/` — donation verifier *(v5.1: was `replication/verification/`)*
9. `agent/` — agent runtime, tool surface, MCP server
10. `deploy/` — autonomous multi-tenant scenarios on a VPS
11. End-to-end flows
12. Strict guarantees
13. Determinism, trust, risk
14. Resource budget
15. Repository layout
16. Verification methodology
17. Testing playbook
18. Known limitations
19. Future work
20. Glossary
21. Where this differs from the v4.0 design

---

## 1. Purpose & research question

The CSE3000 *Communication* sub-project asks: **how should autonomous LLM
agents on a peer-to-peer network agree on a wire protocol without
out-of-band coordination?**

A second, related question shapes the project: **how should those agents
join a community and pay for the right to participate, without relying on
any centralised gatekeeper?**

The two questions converge in one demonstration target. Three motivating
user-facing prompts the system must satisfy by the end of the project:

1. *"What files are stored on our Claw Network?"*
2. *"What files are stored on our Claw Network containing the term
   'Creative Commons'?"*
3. *"Goto the Claw Network, find the Creative Commons Audio Archive 2023
   and play a random file."*

The third prompt is the canonical scenario: a content-seeking LLM agent on
one node finds a file on another node's seedbox, pays a donation to be
admitted, learns the search protocol the seedbox uses (which it had never
seen before), runs SEARCH, downloads the file via BitTorrent, opens it.

The architectural bet behind this project: **the protocol itself becomes
content**. Markdown documents describing IPv8 wire protocols can be
gossipped, hashed, compiled on arrival by the receiver's LLM, and used as
runtime communities. The network can grow new protocols at the same speed
it grows new files — no software releases.

---

## 2. Decisions locked in

A summary of every architectural decision currently active. Each has a §
reference further down.

| Decision | What | §  |
|---|---|---|
| **Admission** | Bitcoin donation to the community's seedbox wallet address; existing member verifies the on-chain TX | 6.1, 8 |
| **Network manifest** *(v5.1)* | Content-hashed `.md` document describing one network's admission policy + genesis peers + default overlays; gossipped via SeedboxCommunity | 6.1, 22 |
| **Mission descriptor** *(v5.1)* | One `mission.md` per agent (Identity / Intent / Budget / Stop); strict parser refuses recipes (no tool names, no ≥3-step lists) | 10.3, 22 |
| **Protocols** | Markdown descriptors compiled at runtime by an LLM into IPv8 `Community` classes; sha1-derived `community_id` | 7 |
| **Sandbox** | AST whitelist + namespaced `exec` (demo-grade; trust gradient is small because peers are admission-gated) | 7.3 |
| **Compiler LLM** | Pluggable `LLMClient` Protocol; **production** is an external GPU-host OpenAI-compatible endpoint via `QWEN_BASE_URL`; local Ollama is the dev/CI fallback | 7.2 |
| **Reasoning LLM** | OpenClaw's chat session (whatever model the chat host runs); driven externally over MCP | 9.4 |
| **Per-node identity** | One BIP-39 seed → three BIP-32 derived keys (IPv8 transport, app-layer signing, Bitcoin HD) | 5 |
| **Bitcoin network** | Testnet (faucet-fundable); switch to mainnet by env var | 5.3 |
| **MCP transport** | FastMCP streamable-HTTP over TCP (matches OpenClaw's expected MCP server shape) | 9.4 |
| **Autonomous scenarios** | Watchdog process per agent polls + drives `openclaw agent` subprocess; declarative stop predicates; YAML manifest | 10 |
| **Multi-tenant** | Multiple scenarios run concurrently on the same VPS, each fully isolated (workspace, ports, seeds, logs) | 10 |
| **Trace** | One JSONL line per watchdog turn — `{ts, agent, turn_n, snapshot, prompt, response, stop_predicate_value}` | 10.4 |

---

## 3. History of the design

### v1–v3 (April 2026) — Exploration

Early-stage reading and prototype scaffolding. Surveyed py-ipv8, MLS,
Signal Double Ratchet, W3C Verifiable Credentials, DIDComm. Built a
toy P2P agent over UDP with append-only logging for accountability.

### v4.0 (2026-05-06) — Trustroom + stake + credentials

The first end-to-end design. Three central abstractions:

- **`TrustroomCommunity`** — a custom IPv8 Community subclass with five
  hand-written message types (`JoinRequest`, `JoinResponse`,
  `ApplicationMessage`, `RoomAdvertisement`, `StakeOp`).
- **`AgentChannel`** (416-line facade) — the single class OpenClaw
  integrated against, gluing community lifecycle, credential
  presentation, stake locking, message routing.
- **`StakeOracle`** + **`StakeOp`** + synthetic-BTC ledger — admission
  gated by a peer locking a stake bond against a *room* (a logical
  partition of the community).

A second-iteration *MCP server* exposed this to OpenClaw as 10 frozen
tools (`delftclaw_lock_for_admission`, `delftclaw_join_room`,
`delftclaw_send_message`, `delftclaw_transfer`, ...).

### 2026-05-08 — The pivot

A working session with the supervisor (and indirectly @grimadas)
identified two architectural ceilings:

1. **Every new protocol = a software release.** Hardcoded Payloads +
   `extra_communities={"name": cls}` at IPv8 boot meant new application
   protocols required pushing Python code to every peer.
2. **Per-agent reasoning was hidden behind a frozen 10-tool surface.**
   The LLM could only do what the tools allowed; new behaviour meant
   new tool code.

The supervisor pointed at the **Agora protocol** (arXiv:2410.11905) and
the **Agent Network Protocol (ANP)** project. The shared idea: agents
negotiate a wire protocol on the fly in natural language, compile their
sides to executable code, and only then exchange typed messages. The
*"protocol document"* (a markdown spec) becomes addressable content
that can be hashed, cached, gossipped, and reused across agents.

The pivot decision: **rip out trustroom/stake/credentials, replace with
markdown-described overlays + Bitcoin-donation admission.** The MCP
surface stays (it's the right OpenClaw integration shape), but the
tools become small primitives over the new substrate.

### v5.0 (2026-05-08 → present) — Markdown overlays + autonomous scenarios

The current state of the codebase. Eight implementation phases brought
us here:

| Phase | Delivered |
|---|---|
| 1 | Bitcoin HD wallet over `bitcoinlib` |
| 2 | Donation admission round-trip (mock + live testnet) |
| 3 | Protocol compiler skeleton (`schema.md`, parser, AST sandbox, LLM interface) |
| 4 | Runtime overlay registration + bootstrap-community extension |
| 5 | First concrete overlay: `content_community.md` |
| 6 | BitTorrent service (libtorrent + stub fallback) |
| 7 | Agent runtime + 12-tool MCP surface |
| 8 | Dead-code cleanup |

A ninth deployment milestone (2026-05-12 → present):

| Phase | Delivered |
|---|---|
| 9 | Autonomous multi-tenant scenarios — templated systemd, watchdog, stop predicates, scenario manifest, `make scenario`/`make watch`/`make stop` |

---

## 4. Architectural overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│  OpenClaw chat host  (reasoning LLM lives here — wherever you talk)      │
│      │                                                                   │
│      │  MCP / streamable-HTTP                                            │
│      ▼                                                                   │
│ ┌────────────────────────────────────────────────────────────────────┐   │
│ │  delftclaw-mcp@<scenario>-<agent>.service  (one per agent on VPS)  │   │
│ │   FastMCP streamable-HTTP server exposing 16 tools (v5.1)                 │   │
│ │   ──────────────────────────────────────────────────────────────   │   │
│ │   OpenClawAgent runtime                                            │   │
│ │     ├─ AgentIdentity        (BIP-32: ipv8 / app / wallet)          │   │
│ │     ├─ IPv8 instance        (transport + endpoint)                 │   │
│ │     ├─ SeedboxCommunity     (bootstrap overlay)                    │   │
│ │     ├─ BitcoinWallet        (bitcoinlib HDWallet)                  │   │
│ │     ├─ BitTorrentService    (libtorrent + stub fallback)           │   │
│ │     └─ OverlayRegistry      (compile + cache + ipv8.overlays.append)│  │
│ │           ▲                                                        │   │
│ │           │ HTTP                                                   │   │
│ │           ▼                                                        │   │
│ │     Compiler LLM (Qwen2.5-Coder 7B on local Ollama)                │   │
│ └────────────────────────────────────────────────────────────────────┘   │
│ ┌────────────────────────────────────────────────────────────────────┐   │
│ │  delftclaw-watchdog@<scenario>-<agent>.service (one per agent)     │   │
│ │   - polls every interval_s seconds                                 │   │
│ │   - builds turn prompt = persona + goal + state + history          │   │
│ │   - subprocesses `openclaw agent --message <prompt>`               │   │
│ │   - evaluates stop predicate; exits with meaningful code           │   │
│ └────────────────────────────────────────────────────────────────────┘   │
│      │                                                                   │
│      │  UDP 8190+                                                        │
│      ▼                                                                   │
│  IPv8 peer-to-peer transport ─── other agents (same or different VPS)    │
│      │                                                                   │
│      │  HTTP                                                             │
│      ▼                                                                   │
│  Bitcoin testnet  (bitcoinlib service providers; faucet-fundable)        │
└──────────────────────────────────────────────────────────────────────────┘
```

Two distinct LLMs operate inside this picture and never overlap:

| Role | Who runs it | When |
|---|---|---|
| Reasoning brain | OpenClaw's chat host | Every user message — picks which tool to call |
| Protocol compiler | Local Ollama on the VPS | Only on first contact with a new `.md` overlay; cached forever after |

---

## 5. `identity/` — seed, BIP-32 derivation, wallets

### 5.1 `Seed` + loaders (`identity/seed.py`)

A 32-byte master `Seed` plus four loader implementations of `SeedSource`:

| Loader | Source | Used by |
|---|---|---|
| `MnemonicSeedSource` | BIP-39 mnemonic (+ optional passphrase) | tests, demos, operator CLI |
| `EnvSeedSource` | `OPENCLAW_SEED` env var (hex) | dev only |
| `KeyringSeedSource` | OS keyring (libsecret / Keychain) | production target |
| `KeyfileSeedSource` | hex-encoded 32-byte file (default `~/.openclaw/identity/seed.txt`); auto-generates if missing | VPS production |

### 5.2 Derivation (`identity/derivation.py`)

One BIP-32 chain (`Bip32Ed25519Kholaw`) with three fixed paths:

| Path | Used for |
|---|---|
| `m/44'/0'/0'/0/0` | IPv8 transport key (Ed25519 via `LibNaCLSK`) |
| `m/44'/0'/0'/1/0` | App-layer signing key (Ed25519 via `cryptography`) |
| `m/44'/0'/0'/2/0` | (legacy — bitcoinlib does its own BIP-32 internally now; see §5.3) |

### 5.3 `AgentIdentity` (`identity/agent_identity.py`)

`AgentIdentity.from_seed(seed, network) -> AgentIdentity` builds:

- `ipv8: IPv8KeyPair` — Ed25519 wrapped as `LibNaCLSK`, used by py-ipv8.
- `app:  AppSigningKey` — Ed25519, raw — used by the signed-log layer.
- `wallet: Wallet` — Bitcoin HD wallet (see below).

Plus three derived properties:

- `agent_id` — `sha256(ipv8_raw_pubkey || network)`, the project-wide
  identifier (typed `AgentId`).
- `network_hash: IdentityHash` — alias of `agent_id`.
- `public_bundle: KeyBundle` — the public-key triple a peer publishes.

### 5.4 `Wallet` (`identity/wallet.py`)

A thin wrapper over `bitcoinlib.wallets.Wallet`. Construction is keyed
by `bitcoinlib.keys.HDKey.from_seed(seed.bytes, network=..., witness_type="segwit")`,
which derives **its own** secp256k1 BIP-32 chain from the same 32-byte
input. Storage lives in bitcoinlib's SQLite DB (per-network, per-seed
name `delftclaw_<network>_<sha256(seed||network)[:8]>`).

Public surface:

```python
wallet.address()             -> "tb1q..."      (bech32, segwit)
wallet.balance_sats(refresh) -> int            (refresh=True scans providers)
wallet.send(to, sats)        -> "<txid>"       (signs + broadcasts)
```

CLI: `python -m identity.wallet --mnemonic '...' {address,balance,send}`.

---

## 6. `communication/` — bootstrap layer + BitTorrent

### 6.1 `SeedboxCommunity` (`communication/community.py`)

The **only** statically-loaded IPv8 community. Two responsibilities:

1. **Admission**: gate new peers behind a verified Bitcoin donation.
2. **Overlay distribution**: ship `.md` protocol descriptors over the
   wire so new overlays can be loaded at runtime by other nodes.

Nine wire messages *(v5.1: was five)*, defined as `@vp_compile`-decorated
`VariablePayload` subclasses:

| msg_id | Name | Fields | Direction |
|---|---|---|---|
| 1 | `JoinRequestPayload` | `donation_txid: varlenH` | joiner → gatekeeper |
| 2 | `JoinResponsePayload` | `accepted: bool` | gatekeeper → joiner |
| 3 | `OverlayOfferPayload` | `md_hash: 20s` | peer → peer |
| 4 | `OverlayRequestPayload` | `md_hash: 20s` | peer → peer |
| 5 | `OverlayDeliveryPayload` | `md_hash: 20s`, `md_text: varlenH` | peer → peer |
| 6 | `ManifestOfferPayload` *(v5.1)* | `md_hash: 20s` | peer → peer |
| 7 | `ManifestRequestPayload` *(v5.1)* | `md_hash: 20s` | peer → peer |
| 8 | `ManifestDeliveryPayload` *(v5.1)* | `md_hash: 20s`, `md_text: varlenH` | peer → peer |
| 9 | `PeerIntroPayload` *(v5.1)* | `wallet_address: varlenH-utf8`, `known_overlays: varlenH-msgpack` | peer → peer (auto-sent on admission accept) |

The community_id literal `b"openclaw_seedbox_v1\x00"` is the network-wide
hand-picked rendezvous string (the only protocol whose id is hand-picked;
every other overlay's id is content-derived).

The manifest trio mirrors the overlay trio bit-for-bit; the separate
ids let a receiver dispatch on intent without parsing the body. The
PEER_INTRO message is auto-sent by both sides of a successful JOIN
round-trip and provides the live wallet address + overlay catalogue
that the state snapshot then surfaces to the LLM.

Joiner-side helpers return `asyncio.Future` for clean async wait:

```python
request_join(gate, txid)    -> Future[bool]
fetch_overlay(peer, hash)   -> Future[bytes]
publish_overlay(md_text)    -> bytes  (the md_hash)
offer_overlay(peer, hash)   -> None
```

Defensive bits:

- `on_overlay_delivery` **re-hashes** the delivered bytes before resolving
  the waiter, so a peer can't deliver arbitrary markdown under another
  hash.
- `MAX_OVERLAY_BYTES = 64 KiB` caps a single descriptor.

### 6.2 `BitTorrentService` (`communication/bittorrent.py`)

A small `Protocol` abstraction with two implementations:

- `LibTorrentService` — wraps `libtorrent.session`. Lazy-imports
  `libtorrent` so the rest of the package loads on machines without the
  native binding.
- `StubBitTorrentService` — in-process fake. `seed(path)` keys `path` by
  a deterministic magnet URI; `add_magnet(uri)` resolves immediately to
  that path. Used by tests + every dev environment without libtorrent.

`build_default_service(save_dir)` picks the real impl if libtorrent is
installed, else the stub.

---

## 7. `protocol/` — markdown overlays + compiler

This is the project's headline contribution. The system that lets a
markdown document describe an IPv8 protocol, gets compiled by an LLM
into a runtime `Community` class, and registered with a live IPv8
instance.

### 7.1 The descriptor schema (`protocol/schema.md`)

Every `*_community.md` / `*_overlay.md` must follow this schema. Strict;
deviations are rejected by the parser before the LLM is ever asked.

Five required top-level headings, in this order:

```
# Identity
# Messages
# Errors
# Dependencies
# Test Vectors
```

#### `# Identity`

Key/value bullet list:

```
- name: content_community
- version: 1.0.0
- description: Search the local content index of an admitted seedbox.
```

The `community_id` is **not** written by hand — it is derived as
`sha1(canonical_md_bytes)[:20]` and verified at compile time against
what the generated class declares.

#### `# Messages`

One level-2 heading per message, with three blocks:

```markdown
## SEARCH_REQUEST

- msg_id: 1

| name  | encoding     | description                                  |
|-------|--------------|----------------------------------------------|
| query | varlenH-utf8 | utf-8 search string; empty returns full index |

### Handler

On receipt of SEARCH_REQUEST, scan the local content index ...
```

Allowed encodings (the compiler validates against this list):

| Encoding | Wire bytes | Python type |
|---|---|---|
| `uint8` | 1 byte | `int` ∈ [0, 255] |
| `uint16-be` | 2 bytes, big-endian | `int` ∈ [0, 2¹⁶) |
| `uint32-be` | 4 bytes, big-endian | `int` ∈ [0, 2³²) |
| `uint64-be` | 8 bytes, big-endian | `int` ∈ [0, 2⁶⁴) |
| `bool` | 1 byte | `bool` |
| `varlenH` | 2-byte big-endian length + raw bytes | `bytes` |
| `varlenH-utf8` | varlenH whose payload is utf-8 | `str` |
| `varlenH-msgpack` | varlenH whose payload is `msgpack.packb` | list/dict/scalar |
| `bytes20` | exactly 20 raw bytes | `bytes` of length 20 |
| `bytes32` | exactly 32 raw bytes | `bytes` of length 32 |

Anything outside this allowlist is a schema error. The list is small
because byte-level ambiguity destroys cross-implementation determinism
— this is the Agora paper's load-bearing concern.

#### `# Test Vectors`

For each message, ≥ 2 `(fields_json, bytes_hex)` pairs. Example:

```
## SEARCH_REQUEST

- fields: {"query": ""}
  bytes: 0000

- fields: {"query": "creative commons"}
  bytes: 0010 437265617469766520436f6d6d6f6e73
```

These are **mandatory**. The compiler runs every test vector after the
LLM produces code: encode the fields, assert the bytes match; decode the
bytes, assert the fields match. Test-vector failures abort overlay
registration before any traffic is sent or received.

Test vectors are how we mitigate non-determinism in the LLM compile
step — they let the compiler reject wire-incompatible code at activation
time, fail-closed, instead of silently producing garbled bytes.

### 7.2 Compiler pipeline (`protocol/compiler.py`)

```
md_text
  → parse_md(md_text)                  structured ParsedOverlay
  → validate_schema(parsed)            cross-section consistency checks
  → canonicalize_md(md_text)           strip trailing ws, normalise CRLF, drop trailing blanks
  → community_id = sha1(canonical)[:20]
  → prompt = _build_user_prompt(parsed, community_id)
  → source = llm.complete(SYSTEM_PROMPT, prompt)
  → strip_code_fences(source)
  → safe_exec(source)                  AST whitelist + namespaced exec
  → assert generated class declares the same community_id
  → run_test_vectors(payload_classes, parsed.test_vectors)
  → CompiledOverlay(community_id, parsed, source, community_class,
                    payload_classes, canonical_md_bytes)
```

Any failure raises `ProtocolCompileError`. The result is a fully-formed
`Type[Community]` ready to register with IPv8.

The LLM client is pluggable via `protocol.llm.LLMClient`:

- `OpenAICompatibleClient(base_url, model_id, api_key)` — talks to any
  OpenAI-compatible `/v1/chat/completions` endpoint (vLLM, TGI,
  llama.cpp, Ollama).
- `StubLLMClient(sources={community_id_hex: python_source})` — keyed by
  community_id; used by tests + the `--compiler-stub` CLI mode.

### 7.3 Sandbox (`protocol/sandbox.py`)

The AST whitelist that runs against every LLM-generated module before
`exec`. Two functions:

- `validate_ast(source)` — walk the AST, raise `SandboxError` on first
  violation.
- `safe_exec(source) -> dict` — validate, then `exec` in a fresh
  namespace with a restricted `__builtins__`.

Allowed imports (anything else → `SandboxError`):

```
ipv8.community, ipv8.lazy_community, ipv8.messaging.lazy_payload,
ipv8.peer, ipv8.peerdiscovery.network, msgpack, struct
```

Forbidden inside the generated module:

- Calls to `eval`, `exec`, `compile`, `open`, `__import__`, `globals`,
  `locals`, `vars`, `delattr`, `setattr`, `getattr`, `input`,
  `breakpoint`.
- Attribute access on `__class__`, `__bases__`, `__subclasses__`,
  `__mro__`, `__globals__`, `__builtins__`, `__dict__`,
  `__init_subclass__`, `__import__`, `__loader__`, `__spec__`.
- `with` and `async with` blocks.
- `global` and `nonlocal` statements.

This is **demo-grade** sandboxing. The trust gradient is small because
overlays only run after the peer has been admission-gated by donating
to the seedbox, but the AST walk still rejects the obvious foot-guns.
For a production deployment, swap for subprocess+seccomp or WASM
without changing the public API.

### 7.4 Runtime registration (`protocol/registry.py`)

`OverlayRegistry` is the bridge from compiled class → live IPv8.

```python
reg = OverlayRegistry(ipv8, llm_client)
overlay_instance = reg.load(md_text)         # idempotent on community_id
```

Internally:

1. Compile (cached by `community_id`).
2. Build `CommunitySettings(my_peer, endpoint, network)` cribbed from
   any already-loaded overlay (they all share the same IPv8 instance).
3. Instantiate the new community class with those settings.
4. `ipv8.overlays.append(instance)` under `ipv8.overlay_lock`.
5. Call `instance.started()` to register peer observers / start tasks.

IPv8 routes incoming UDP packets to the new community automatically —
`Community.__init__` registers a 22-byte prefix listener on the shared
endpoint (`ipv8/messaging/interfaces/endpoint.py:_prefix_map`). No
monkey-patching. No restart.

### 7.5 Configuration: how an overlay actually gets onto a node

Three concrete entry points. The third is the network-driven path that
the whole design hinges on.

**(a) Boot-time `--publish-overlay PATH`** — operator-driven. The CLI
reads the file, calls `publish_overlay` which both serves it and locally
compiles+registers it. This is how a seedbox declares what it serves.

**(b) In-LLM `overlay_publish(md_text)`** — agent-driven, same effect as
(a) but at runtime. The LLM can ship a new protocol mid-conversation.

**(c) Network arrival — the zero-shot path.** A peer offers an overlay
via `OVERLAY_OFFER(md_hash)`. The receiving agent calls
`overlay_fetch_and_load(peer_mid, md_hash)`, which sends
`OVERLAY_REQUEST`, awaits `OVERLAY_DELIVERY`, **re-hashes** the
delivered bytes to verify, then runs the same `OverlayRegistry.load(...)`
pipeline as (a) and (b). No human intervention.

All three funnel through `compile_overlay()` then
`ipv8.overlays.append()`. The content-hashed `community_id` guarantees
that two nodes which loaded the same descriptor — by any path — are on
the same overlay by construction.

### 7.6 Why markdown vs the traditional approach

The traditional way: every IPv8 protocol is a hand-written `Community`
subclass, payloads are `@vp_compile`-decorated classes in source code,
the IPv8 boot config registers them via `extra_communities={"Foo":
FooCommunity}`. That is what the deleted trustroom layer did. We do
**not** do that for the content/search overlays.

| | Traditional | Markdown + runtime compile |
|---|---|---|
| **Pros** | Type-safe at edit time; reviewable in one file; deterministic by construction; no LLM dependency; zero cold-start; trivial sandbox; mature debugging | Protocol-is-content; zero-shot adoption; intrinsic versioning (sha1 of canonical text); cross-stack portability; single source of truth; mandatory test vectors; dependency composition |
| **Cons** | Every new protocol is a software release; network can't carry its own extensibility; `community_id` hand-picked (no collision protection); cross-stack reimplementation; prose drifts from code | LLM non-determinism (mitigated, not eliminated); cold-start LLM round-trip; hard dependency on a reachable model; expanded trust boundary (incoming markdown → local code-gen); three-artefact debugging; weaker tooling for the prose half |

The architectural bet: for an agentic P2P network where peers are
LLM-driven, new content types appear constantly, and heterogeneous
runtimes will eventually need to interoperate — the *current* cons
(cold-start latency, non-determinism risk, trust boundary) are
tractable engineering problems with known mitigations; the *traditional*
cons (every protocol is a software release, no in-network extensibility)
are architectural ceilings. Same bet Agora and ANP make.

The bootstrap `SeedboxCommunity` stays hand-written deliberately —
it's stable, security-critical, the admission gate. Markdown is for
everything else.

---

## 8. `admission/` — donation verifier

*(v5.1: file moved from `replication/verification/donation_verifier.py`
to `admission/donation_verifier.py`. The `replication/` package retains
other unrelated subproject code.)*

`DonationVerifier` (in `admission/donation_verifier.py`)
is the gatekeeper-side check. Given a txid claimed by a joiner:

```python
verifier = DonationVerifier(
    seedbox_address="tb1qexample...",
    min_sats=10000,
    min_confirmations=1,
    network="testnet",
)
result = verifier.verify(txid_hex)
# DonationVerification(accepted, reason, paid_sats, confirmations)
```

Behind the scenes: lazy-constructs `bitcoinlib.services.services.Service`
on first `verify()` call (because `Service.__init__` probes the provider
pool synchronously over the network — blocking that at agent boot was
causing systemd timeouts; deferring fixes it). Fetches the transaction,
walks outputs, returns the first one paying `seedbox_address` with
`value >= min_sats` and `confirmations >= min_confirmations`. Any
provider exception is caught and surfaced as `accepted=False,
reason="fetch_failed:..."` — the caller decides to retry.

---

## 9. `agent/` — runtime, tool surface, MCP server

### 9.1 `OpenClawAgent` (`agent/runtime.py`)

The single owner of the per-node stack. Constructor takes an
`AgentIdentity`, a compiler `LLMClient`, an `AgentConfig`, and
(optionally) a `BitTorrentService`. `await agent.start()` builds the
IPv8 instance, loads the bootstrap `SeedboxCommunity`, wires a
`DonationVerifier` pointing at the agent's own wallet address as the
seedbox, and creates an `OverlayRegistry`. `await agent.stop()` tears
all of it down.

Runtime methods used by both tests and the MCP server:

- `add_peer(host, port, pubkey_hex)` — pre-introduce a peer to every
  loaded overlay's IPv8 network (no walker / DispersyBootstrap).
- `publish_overlay(md_text)` — serve + locally compile+register.
- `known_peers()` — union across all overlays.
- Plus the read-only properties `address`, `pubkey_hex`, `seedbox`,
  `registry`, `wallet`, `bittorrent`.

### 9.2 Tool surface (`agent/tools.py`)

A `ToolRegistry` of 16 tools the LLM can call *(v5.1: was 13)*. `build_tools(agent)`
constructs the registry bound to one agent.

| Tool | Effect |
|---|---|
| `peers_list` | list peers known on any overlay |
| `peer_add` | pre-introduce a peer at runtime (since v9, used by `scenario_boot`) |
| `wallet_address` | this agent's testnet receiving address |
| `wallet_balance` | balance in sats (refreshes from network) |
| `wallet_send` | sign + broadcast a payment, return txid |
| `seedbox_donate_and_join` | wallet.send → JOIN_REQUEST → await JoinResponse |
| `overlays_list` | compiled overlays loaded locally — **v5.1**: now returns full per-message field schemas + handler text + errors + dependencies |
| `overlay_describe` *(v5.1)* | return the canonical markdown of a loaded overlay (32 KiB cap) |
| `overlay_fetch_and_load` | OVERLAY_REQUEST from a peer → compile → register |
| `overlay_publish` | serve a `.md` over OVERLAY_REQUEST |
| `overlay_invoke` | generic dispatcher: send a message on any compiled overlay |
| `agent_inject_manifest` *(v5.1)* | parse + cache a network manifest; pre-introduces its genesis peers |
| `network_join` *(v5.1)* | end-to-end admission: parse → peer_add → fetch default overlays → donate → JOIN_REQUEST; uses cached manifest if no arg |
| `torrent_seed` | begin seeding a local file, return magnet |
| `torrent_fetch` | download a magnet URI, return saved path |
| `torrent_stats` | snapshot of all downloads + seeds |

`overlay_invoke` is what closes the loop: once the registry has compiled
a class, the LLM can call any message in it by name without the runtime
having ever statically known about that protocol.

### 9.3 LLM tool-call loop (`agent/loop.py`)

The **offline-test** path. Used by `examples/run_two_agents.py` and the
in-process test suite. Drives an `OpenAICompatibleToolLLM` (production
shape) or a `StubToolLoopLLM` (scripted, for tests) through the standard
OpenAI tool-calls loop: messages → response → optionally tool_calls →
dispatch → next round-trip.

Not used in production. Production goes through the MCP server (§9.4).

### 9.4 MCP server (`agent/mcp_server.py`)

The **production** path. A FastMCP streamable-HTTP server wrapping the
`OpenClawAgent` and exposing the 16 tools. OpenClaw's chat session
connects to this server over HTTP. The OpenClaw chat host's LLM (the
reasoning brain) calls our tools; the local Qwen on the VPS only does
overlay compilation when triggered.

CLI: `python -m agent ... mcp --mcp-host 0.0.0.0 --mcp-port 8765`.

The watchdog (§10) drives `openclaw agent --message <prompt>` which in
turn talks to the MCP server. Two LLMs in the picture, no overlap:

- OpenClaw's LLM picks the tool to call.
- Local Qwen compiles overlays.

### 9.5 CLI (`agent/cli.py`)

`python -m agent ...` exposes:

| Subcommand | Use |
|---|---|
| `info` | print this agent's identity/address/pubkey/wallet, exit |
| `mcp` | **production** — serve the 16-tool surface over FastMCP streamable-HTTP |
| `run` | offline-test — execute one query via the internal LLM loop |
| `serve` | offline-test — long-running stdin/stdout via the internal loop |

Boot-time flags drive per-agent configuration:

```
--publish-overlay PATH    repeatable; load + serve a .md at boot
--peer HOST:PORT:PUBKEY    repeatable; pre-introduce a peer
--system-prompt PATH       override the default LLM persona (offline-test paths)
--compiler-stub            offline mode for the protocol compiler
--llm-stub-script PATH     offline mode for the tool-call loop
```

---

## 10. `deploy/` — autonomous multi-tenant scenarios

This is the layer that lets the supervisor see two OpenClaw agents
talking to each other on a single VPS without keyboard input.

### 10.1 Per-VPS process layout

```
ollama.service                                  (shared compiler LLM)

delftclaw-mcp@<scenario>-<agent>.service        (one per agent)
    runs `python -m agent ... mcp` bound to that agent's ports

delftclaw-watchdog@<scenario>-<agent>.service   (one per agent)
    runs `python -m deploy.watchdog` — the polling loop
```

### 10.2 Operator interface

```bash
make scenario NAME=seek_cc      # rsync + python -m deploy.scenario_boot seek_cc
make watch    NAME=seek_cc      # journalctl -fu 'delftclaw-{mcp,watchdog}@seek_cc-*'
make stop     NAME=seek_cc      # python -m deploy.scenario_boot seek_cc --teardown
make scenarios                  # list running scenarios + agents
```

All four are thin SSH wrappers; they execute on the VPS via the
operator's `ssh delftclaw@<vps>`.

### 10.3 Scenario manifest (`deploy/scenarios/<name>/scenario.yaml`)

The single source of truth for what a scenario looks like. Strict
schema; validated at parse time by `deploy/scenario.py`.

Example (`deploy/scenarios/seek_cc/scenario.yaml`):

```yaml
name: seek_cc
description: Bob finds and downloads a Creative Commons file from Alice's seedbox.

watchdog:
  interval_s: 30
  max_iterations_per_turn: 8
  max_total_turns: 50
  max_wall_clock_s: 1800

observability:
  log_dir: /var/log/delftclaw/scenarios/seek_cc

agents:
  alice:
    ipv8_port: 8190
    mcp_port: 18765
    publish_overlays:
      - protocol/examples/content_community.md
    mission_file: alice/mission.md       # v5.1: was persona_file + goal_file
    stop_predicate: never
    seed_content:
      - magnet: "magnet:?xt=urn:btih:...&dn=cc_audio_2023.mp3"
        name: "Creative Commons Audio Archive 2023.mp3"
        size: 4200000
        mime: audio/mpeg
        tags: [cc, audio]

  bob:
    ipv8_port: 8191
    mcp_port: 18766
    publish_overlays: []
    mission_file: bob/mission.md         # v5.1: was persona_file + goal_file
    stop_predicate: torrent_progress_gte_1
    peers:
      - alice
```

The parser rejects: missing required keys, unknown stop predicate
names, peer references to unknown or self-agents, port collisions,
ports outside `[1024, 65535]`, missing overlay paths, missing
mission files. v5.1 also rejects legacy `persona_file` / `goal_file`
keys with a clear migration error, and re-parses each mission via
``deploy.mission.parse_mission`` (which refuses recipes — see §22).
Tested in `tests/test_scenario_manifest.py`.

### 10.4 Watchdog turn protocol (`deploy/watchdog.py`)

Each tick:

```
1. snapshot = collect_state(agent)              # in-process, no MCP round-trip
2. if stop_predicate(snapshot):
       log({reason: "stop_predicate_satisfied"}); exit 0
3. if turn_n >= max_total_turns:
       log({reason: "max_total_turns"}); exit 1
4. if elapsed >= max_wall_clock_s:
       log({reason: "max_wall_clock_s"}); exit 2
5. prompt = build_turn_prompt(persona, goal, snapshot, history)
6. subprocess: openclaw agent --agent <instance> --message <prompt> --json
7. log_jsonl({turn_n, prompt, response, snapshot, stop_predicate_value})
8. sleep tick_remaining
9. goto 1
```

The state snapshot is built **server-side** by `deploy.state_snapshot.collect_state`
(read-only access to the in-process `OpenClawAgent` — peers, wallet,
overlays, torrents). The LLM receives the snapshot as text inside the
prompt.

Exit codes are meaningful:

| Code | Reason |
|---|---|
| 0 | stop predicate satisfied |
| 1 | max_total_turns reached |
| 2 | max_wall_clock_s reached |
| 3 | N consecutive `openclaw agent` subprocess failures |

The systemd unit sets `Restart=no` — exit codes are signals to the
operator, not crash-recovery opportunities.

### 10.5 Stop-predicate library (`deploy/stop_predicates.py`)

Predicates are pure functions of the snapshot dict. The watchdog
evaluates them; the LLM never decides termination.

Registry:

| Name | Triggers when |
|---|---|
| `never` | always False (long-running seedboxes) |
| `torrent_progress_gte_1` | any torrent in `torrent_stats` has `progress >= 1.0` |
| `peer_count_gte_N(n=...)` | `peers_list` returns ≥ N peers |
| `wallet_received_sats(min_sats=...)` | balance has grown ≥ min_sats vs scenario start |

Names with parentheses pass keyword args (parsed by a small regex
resolver, no `eval`). New predicates are added by registering a
callable in the module's `_REGISTRY` dict.

### 10.6 `scenario_boot.py` orchestration

`python -m deploy.scenario_boot <name>` does, in order:

1. Parse the manifest (fail-fast on schema errors).
2. For each agent: create state dirs, generate a deterministic seed
   file if missing, write the per-instance systemd env file at
   `/etc/delftclaw/instances/<scenario>-<agent>.env`, stage persona +
   goal under `/etc/delftclaw/scenarios/<scenario>-<agent>/`.
3. `systemctl enable --now delftclaw-mcp@<instance>.service` per agent.
4. Wait until each MCP server's port answers.
5. Provision each agent's per-`HOME` OpenClaw workspace:
   `openclaw mcp set <instance> '{"url": ..., "transport": ...}'` and
   `openclaw agents add <instance> --workspace ... --agent-dir ... --model ollama/<qwen>`.
6. Collect (host, port, pubkey_hex) per agent. Pubkey is derived
   locally from the seed file (no extra MCP tool needed).
7. Cross-introduce peers: for every `agents.X.peers: [Y]`, call X's
   `peer_add` MCP tool with Y's coordinates.
8. `systemctl enable --now delftclaw-watchdog@<instance>.service` per
   agent.

`--dry-run` prints the plan without touching the system. `--teardown`
stops services, removes env files, deletes the OpenClaw agent
registrations (seed files persist so identities survive teardowns).

### 10.7 Strict guarantees

Each of these is enforced in code, not by convention:

1. **Zero hidden human input.** Every turn's prompt is built
   deterministically from {persona.md, goal.md, snapshot, last-N
   turns}. No keyboard.
2. **Bounded resource use.** Three caps:
   `max_iterations_per_turn` (LLM tool calls per `openclaw agent` run),
   `max_total_turns` (watchdog ticks),
   `max_wall_clock_s` (scenario-wide).
3. **Stop predicates are declarative.** Named functions resolved at
   parse time. The LLM never declares "done."
4. **Per-scenario state isolation.** Each agent has its own OpenClaw
   profile (via `HOME=`), wallet seed, bitcoinlib data dir, MCP port,
   IPv8 port, and JSONL log file.
5. **Idempotent boot.** Re-running `make scenario NAME=...` cleanly
   restarts from declared initial state.
6. **Auditable trace.** One JSONL line per turn. Reproducible replay.
7. **No silent failures.** Watchdog exit codes 0/1/2/3 are
   distinguishable.

### 10.8 First concrete scenario: `seek_cc`

Alice publishes `content_community.md`, seeds one Creative Commons
audio file into the index, never stops. Bob is cross-introduced to
Alice, donates 10000 sats, fetches the content community descriptor,
runs SEARCH, downloads the magnet, exits via
`torrent_progress_gte_1`.

End-to-end demo (single command on the operator's laptop):

```
make scenario NAME=seek_cc
make watch    NAME=seek_cc
```

Expected runtime: 5–10 minutes on Hostinger KVM 2 with cold-loaded
Qwen.

---

## 11. End-to-end flows

### 11.1 Donation-gated admission

```
Joiner (Alice)                          Gatekeeper (Bob)
   |                                            |
   |  Wallet.send(bob_addr, 10000 sats)         |
   |---broadcast txid to Bitcoin testnet------->|  (out-of-band)
   |                                            |
   |  request_join(bob_peer, txid_bytes)        |
   |---JOIN_REQUEST(txid)---------------------->|
   |                                            |
   |                                   DonationVerifier.verify(txid):
   |                                     fetch via bitcoinlib.Service
   |                                     check output to bob_addr
   |                                     check >= min_sats
   |                                     check >= min_confirms
   |                                            |
   |                                   if accepted:
   |                                     network.add_verified_peer(alice)
   |                                            |
   |<--JOIN_RESPONSE(accepted=True)-------------|
   |                                            |
   future.set_result(True)
```

### 11.2 Overlay discovery + compile + register

```
Publisher (Alice)                       Consumer (Bob)
   |                                       |
   publish_overlay(content_md)             |
     md_hash = sha1(canonical)[:20]        |
     _published[md_hash] = content_md      |
   |                                       |
   offer_overlay(bob, md_hash)             |
   |---OVERLAY_OFFER(md_hash)------------->|
   |                                       |
   |                                       fetch_overlay(alice, md_hash)
   |<--OVERLAY_REQUEST(md_hash)------------|
   |                                       |
   md_text = _published[md_hash]           |
   |---OVERLAY_DELIVERY(hash, md_text)---->|
   |                                       |
   |                                       sha1(canonical(text)) == md_hash?
   |                                       future.set_result(md_text)
   |                                       |
   |                                       registry.load(md_text):
   |                                         compile_overlay(md_text, llm)
   |                                           parse + schema validate
   |                                           derive community_id
   |                                           LLM → python source
   |                                           AST validate + safe_exec
   |                                           run test vectors
   |                                         instantiate(class)
   |                                         ipv8.overlays.append(instance)
   |                                         instance.started()
   |                                       |
   Bob now speaks the same protocol as Alice on a new community.
```

### 11.3 Autonomous content SEARCH (the seek_cc demo)

```
T+00s   scenario_boot wrote /etc/delftclaw/instances/seek_cc-{alice,bob}.env
T+02s   systemd: delftclaw-mcp@seek_cc-{alice,bob}.service: Started
T+04s   scenario_boot: openclaw mcp set + agents add per HOME
T+05s   scenario_boot: peer_add bob -> alice OK
T+05s   systemd: delftclaw-watchdog@seek_cc-{alice,bob}.service: Started
T+06s   bob.watchdog turn=1: collect_state {peers=1, overlays=1, wallet=0}
T+06s   bob.watchdog turn=1: subprocess openclaw agent
T+30s   bob.watchdog turn=1: response — "I should donate to alice"
        tool_calls=[seedbox_donate_and_join(...)]
T+30s   bob.watchdog turn=1: stop_predicate=False
T+60s   bob.watchdog turn=2: state shows admission accepted
        tool_calls=[overlay_fetch_and_load(alice_mid, content_md_hash)]
T+100s  bob.watchdog turn=3: overlay loaded
        tool_calls=[overlay_invoke(content_md_hash, SEARCH_REQUEST,
                                    fields={query: "creative commons"})]
T+130s  bob.watchdog turn=4: state shows response_cache populated
        tool_calls=[torrent_fetch(magnet)]
T+200s  bob.watchdog turn=5: torrent_stats progress=0.42
T+360s  bob.watchdog turn=7: torrent_stats progress=1.00
T+361s  bob.watchdog: stop_predicate_satisfied; exit 0
T+361s  alice.watchdog continues (stop_predicate=never)
```

---

## 12. Strict guarantees

Centralised list of every guarantee the system enforces in code. Each
links to the §-level section where the mechanism is documented.

| Guarantee | Where enforced | § |
|---|---|---|
| `community_id` is content-derived (no human override) | `compiler.compile_overlay` asserts the generated class declares the right id | 7.2 |
| Overlay delivery cannot lie about its hash | `SeedboxCommunity.on_overlay_delivery` re-hashes before resolving | 6.1 |
| Generated overlay code cannot escape the sandbox (demo-grade) | `sandbox.validate_ast` rejects non-allowlisted imports / dunders / unsafe builtins | 7.3 |
| Generated overlay cannot produce wire-incompatible bytes | `compile_overlay` runs every `.md` test vector before activation | 7.1, 7.2 |
| Markdown descriptors above 64 KiB are dropped | `MAX_OVERLAY_BYTES` cap in `SeedboxCommunity` | 6.1 |
| Donation verifier never blocks agent boot | Lazy `Service(...)` construction; `_get_service()` runs on first `verify()` | 8 |
| Scenarios fail-fast on bad manifest | `scenario.parse_scenario` rejects unknown predicates, peer refs, port collisions | 10.3 |
| Watchdog cannot run indefinitely | Three caps: `max_iterations_per_turn`, `max_total_turns`, `max_wall_clock_s` | 10.4 |
| LLM never declares scenario "done" | Stop predicates are pure functions evaluated by the watchdog | 10.5 |
| Every turn is reproducible from log alone | JSONL line per turn with prompt+response+snapshot | 10.4 |
| Each agent's state is fully isolated | per-`HOME` OpenClaw config, per-instance env file, per-agent seed + wallet + log | 10.7 |
| Watchdog exit codes are distinguishable | 0 / 1 / 2 / 3 = predicate / turn cap / wall clock / LLM errors | 10.4 |

---

## 13. Determinism, trust, risk

Risks vs mitigations, with reference to where the mitigation lives in
the code.

| Risk | Severity | Mitigation |
|---|---|---|
| Two LLMs producing different wire bytes for the same `.md` | High (architectural) | Strict encoding allowlist (§7.1); mandatory test vectors gate activation (§7.2); cache key includes `model_id` + `model_version` |
| Malicious peer ships a `.md` that triggers code execution | High | AST whitelist (§7.3); donation-admission gate restricts who can offer overlays at all (§6.1); 64 KiB descriptor cap |
| Peer delivers markdown that doesn't match the claimed hash | Medium | `on_overlay_delivery` re-hashes before resolving the future (§6.1) |
| Compile latency on first contact with a new overlay | Medium | Local Ollama on the VPS (no network hop); cached per `community_id` |
| Local LLM unreachable (Ollama outage) | Medium | Cached overlays continue working; new-overlay adoption blocks; fallback to natural-language messaging on the bootstrap community (Agora-style) |
| Watchdog hangs forever waiting for an LLM response | Low | Three caps; subprocess timeout = `interval_s + 30s` |
| Bitcoin testnet provider outage | Low | `bitcoinlib.services.Service` rotates providers; `DonationVerifier.verify` catches and returns a typed error |
| Bob never finds Alice's wallet address in state snapshot | Medium | Known gap — Bob's goal.md explicitly says to wait when address isn't visible. Fixable by plumbing peer wallet addresses into the snapshot (small follow-up) |
| `openclaw agent` not on `PATH` for the watchdog | Low | `setup_vps.sh` warns at install; watchdog exits 3 if subprocess fails repeatedly |
| `qwen2.5-coder:7b` is too small to generate correct overlay code | Medium | Test vectors catch wire-level errors at activation, so failures are loud; can swap to a larger model via `QWEN_MODEL` env var |
| **Mock-mode admission auto-admits any txid** *(post-merge)* | High in production / acceptable for demo | `DonationVerifier(network="mock")` is the default for v5.1 + the synthetic wallet. Donation gate is ceremonial in mock mode. Flip to `BTC_NETWORK=testnet` in `configs/host.env` for real on-chain verification. |
| **Hand-written Python overlays escape the markdown sandbox** *(post-merge)* | High | `register_community(cls)` runs whatever `Community` subclass the operator imports — no AST whitelist, no test vectors. By design (this is the escape hatch for static experiments); local-only because nothing wire-transmittable references the class. Reviewers must audit the source the same way they audit any other module the agent imports. |

---

## 14. Resource budget

Per scenario with N agents on a single Hostinger KVM 2 (8 GB / 2 vCPU):

| Component | Footprint |
|---|---|
| Ollama (shared, once warm) | ~5 GB resident |
| Each `delftclaw-mcp@*` | ~150 MB |
| Each `delftclaw-watchdog@*` | ~100 MB |
| `openclaw agent` subprocess (per active turn) | ~250 MB transient |

Steady-state for a 2-agent scenario: ~5.7 GB resident. Peak during
overlapping turns: ~6.2 GB. **Two concurrent 2-agent scenarios is the
practical ceiling on KVM 2.**

For larger demos: KVM 8 (32 GB / 8 vCPU) holds 14B Qwen comfortably,
or move the compiler LLM off the agent VPS to a dedicated GPU host
reached over Tailscale (see §18 — future work).

---

## 15. Repository layout

```
identity/                          # seed → BIP-32 → ipv8/app/wallet keys
  seed.py                          # Seed + 4 SeedSources
  derivation.py                    # IPV8_PATH / APP_PATH / WALLET_PATH
  ipv8_key.py                      # LibNaCLSK from derived bytes
  app_key.py                       # Ed25519 from derived bytes
  wallet.py                        # bitcoinlib HDWallet; CLI: `python -m identity.wallet`
  agent_identity.py                # the multi-key bundle

communication/
  community.py                     # SeedboxCommunity (the only static community)
  bittorrent.py                    # BitTorrentService Protocol + Stub + LibTorrent

protocol/                          # the .md overlay system
  schema.md                        # canonical descriptor format
  compiler.py                      # parse → validate → LLM → AST → exec → test vectors
  llm.py                           # LLMClient Protocol; OpenAICompat + Stub
  sandbox.py                       # AST whitelist + namespaced safe_exec
  registry.py                      # OverlayRegistry — runtime ipv8 registration
  examples/
    echo_overlay.md                # smallest round-trip overlay
    echo_overlay_stub.py
    content_community.md           # the SEARCH overlay
    content_community_stub.py

replication/verification/
  donation_verifier.py             # bitcoinlib-backed txid → DonationVerification

agent/                             # the per-node process
  runtime.py                       # OpenClawAgent
  tools.py                         # the 13 LLM-callable tools
  loop.py                          # offline-test internal tool-call loop
  mcp_server.py                    # production FastMCP streamable-HTTP server
  cli.py                           # `python -m agent {info,mcp,run,serve}`

deploy/                            # autonomous-scenario infrastructure
  setup_vps.sh                     # idempotent VPS bootstrap
  scenario.py                      # strict YAML manifest parser
  scenario_boot.py                 # the orchestrator
  watchdog.py                      # per-agent polling loop
  state_snapshot.py                # collect_state() — JSON-serialisable snapshot
  stop_predicates.py               # registry + 4 named predicates
  turn_builder.py                  # pure-function turn-prompt assembly
  probe_mcp.py                     # MCP client probe (list tools / call one)
  systemd/
    delftclaw-mcp@.service         # templated MCP unit
    delftclaw-watchdog@.service    # templated watchdog unit
    delftclaw-gateway.service.template       (colleague's; out of scope)
    delftclaw-seedbox-audit.service.template (colleague's; out of scope)
  scenarios/
    _shared/personas/
      seedbox.md
      content_seeker.md
    seek_cc/
      scenario.yaml
      alice/{persona,goal}.md
      bob/{persona,goal}.md

examples/                          # runnable demos
  donation_demo.py                 # admission round-trip
  overlay_demo.py                  # ship .md, compile, use
  run_two_agents.py                # two real `python -m agent` processes
  ipv8_hello/                      # minimal IPv8 reference (kept as template)

redteam/primitives/                # signed append-only log (research artefact)
  signed_log.py
  peer_log.py
  verify.py

security/                          # colleague's gateway + experiments (out of scope)

tests/                             # in-tree pytest suite (44 tests)
test_signed_log.py                 # top-level redteam suite (132 tests)
test_signed_verify.py              # plus the FastMCP/IPv8 tests above
test_peer_log.py

docs/
  architecture.md                  # short developer-facing reference
  ...                              # other in-progress notes
Makefile                           # operator entry: make deploy / scenario / watch / stop / test
PROJECT_DESIGN.md                  # this file
```

---

## 16. Verification methodology

The project is evaluated against four progressively-realistic test
layers. Each layer must pass before the next is exercised.

### Layer 1 — Unit/integration suite (~80 s, no network)

```
make test
```

Covers:

- Protocol compiler (parse, schema validate, sandbox AST whitelist,
  test-vector enforcement, end-to-end compile via stub LLM).
- Overlay registry (publish/fetch/hash-verify, idempotent registration,
  remote-fetched overlay message round-trip).
- Content community (descriptor compiles, multi-result substring +
  tag search, empty-query full-index).
- BitTorrent stub (seed↔fetch, default fallback to stub).
- Agent runtime (start/stop, tool surface in-process, full internal
  LLM loop drives a scripted SEARCH).
- Agent MCP server (FastMCP `Client` round-trip, peer_add).
- Stop predicates (11 unit cases).
- Scenario manifest (12 cases: happy path + 11 rejections).
- Watchdog turn builder (16 cases: history truncation, deterministic
  prompts, caps).
- Signed append-only log (132 cases — the redteam suite).

**Expected**: 212 passed. Anything red is a regression.

### Layer 2 — End-to-end two-process demo (~30 s, no network)

```
python -m examples.run_two_agents
```

Spawns two real `python -m agent` processes (Alice publisher + Bob
consumer), drives Bob through a scripted tool loop, tears Alice down.
Closest "real run" without a live LLM endpoint or testnet wallet.

**Expected**: ends with `"Asked Alice; the SEARCH_REQUEST was sent on
the content community."`

### Layer 3 — Per-component CLI smoke

- `python -m identity.wallet --mnemonic '...' address` → bech32 address
- `python -m examples.donation_demo --mock-verifier` → ACCEPTED log line
- `python -m examples.overlay_demo` → echo round-trip
- `python -m agent ... info` → agent info JSON

### Layer 4 — Live VPS run

```
make deploy                     # one-time infrastructure refresh
make scenario NAME=seek_cc      # full autonomous demo
make watch    NAME=seek_cc      # observe until Bob exits 0
```

Expected: Bob's watchdog journal ends with `stop_predicate_satisfied;
exit 0` within ~10 minutes. Alice keeps running until `make stop`.

---

## 17. Testing playbook

For day-to-day work:

```bash
make test                       # ~80 s, all layers 1
make clean                      # remove __pycache__ + .pytest_cache
```

For pre-deployment confidence:

```bash
make test
python -m examples.run_two_agents
python -m identity.wallet --mnemonic '...' address
python -m examples.overlay_demo
```

For deploy validation:

```bash
make deploy                     # idempotent infrastructure bootstrap
make scenario NAME=seek_cc      # bring up the demo scenario
make watch    NAME=seek_cc
make stop     NAME=seek_cc
```

For per-agent introspection on the VPS:

```bash
make ssh
sudo -u delftclaw env PYTHONPATH=/opt/delftclaw HOME=/var/lib/delftclaw/seek_cc/bob \
    /opt/delftclaw/venv/bin/python -m deploy.probe_mcp \
    http://127.0.0.1:18766/mcp                       # list tools
sudo tail -f /var/log/delftclaw/scenarios/seek_cc/bob.jsonl | jq
```

---

## 18. Known limitations

The system runs end-to-end, but the following are not yet addressed.
Each is a candidate for follow-up work.

1. **Peer wallet addresses are not in the state snapshot.** Bob can see
   Alice's `mid_hex` and `address` (IPv8 endpoint) but not her wallet
   address. Bob's goal.md says to wait if absent; in practice he stalls
   until a human resolves it. **Fix**: add a `peer_addresses_map` field
   to the snapshot, populated by a new tool that fetches each peer's
   wallet via cross-MCP call.
2. **The sandbox is demo-grade.** AST whitelist + `exec` in a fresh
   namespace. A determined adversary could bypass this. **Fix**:
   subprocess + seccomp (Linux-only) or WASM via wasmtime (cross-
   platform). Adds IPC overhead.
3. **`qwen2.5-coder:7b` non-determinism.** Two compiles of the same `.md`
   *should* produce byte-identical code at `temperature=0.0`, but in
   practice the model occasionally varies. Test vectors catch the worst
   failures (wire-level mismatches); subtle handler-semantics drift can
   slip through. **Mitigation**: use the in-band stub-source path
   (`*_stub.py` siblings of the `.md`) for known overlays.
4. **No replay tooling for JSONL logs.** The log captures everything,
   but no script exists to step through a recorded scenario. **Fix**:
   ~50 LOC of a `deploy/replay.py` that re-renders prompts + responses.
5. **Single-VPS scenarios only.** Cross-VPS demos need either a real
   public IP for IPv8 UDP or a Tailscale mesh. The architecture
   supports it (`scenario_boot.py:coords['host']` is hardcoded to
   `127.0.0.1`); needs a `cross_vps:` block in the manifest.
6. **No `peer_add` security model.** Any caller with MCP access can
   introduce arbitrary peers. The donation gate still protects
   admission-required overlays, but the bootstrap community is open.
   **Fix**: require an HMAC-signed introduction token.
7. **Watchdog doesn't survive VPS reboot.** Each scenario must be
   re-launched with `make scenario`. By design — exit codes are
   meaningful — but a `Wants=` directive that persists scenario
   selection across reboots would be useful.
8. **Manifest validator doesn't warn on combined RAM exceeding the
   budget.** Multiple scenarios can be brought up concurrently and
   together exceed 8 GB; OOM kills the watchdog. **Fix**: estimate
   per-agent footprint, sum, warn at parse time.

---

## 19. Future work

In rough priority order:

1. **Plumb peer wallet addresses into the state snapshot** (closes the
   most-observable demo gap).
2. **Add `replay.py` for JSONL log time-travel** — operator can step
   through a recorded scenario without re-running.
3. **`stop_predicate_torrent_progress_gte_1_and_played`** — extends the
   demo to "file was downloaded *and opened*", making the third
   motivating prompt fully autonomous.
4. **Multi-VPS scenarios** — extend `scenario.yaml` with a `vps:` field
   per agent; teach `scenario_boot.py` to remote-execute on the named
   VPS.
5. **Stronger sandbox** — move to subprocess + seccomp (Linux) before
   any deployment beyond research demos.
6. **HMAC-signed peer introduction tokens** — close the bootstrap-
   community spoofing gap.
7. **`compile_overlay` cache on disk** — currently in-memory only, lost
   on agent restart. Recompiling the same `.md` after restart costs an
   LLM call per overlay.
8. **A second concrete scenario** — for the supervisor to see something
   other than `seek_cc`. Candidates: pure overlay-discovery (no
   payment), reputation gossip, content-replication.

---

## 20. Glossary

| Term | Meaning |
|---|---|
| **Agent** | An LLM-driven peer on the network. One `OpenClawAgent` per Python process; one Python process per VPS-scenario tenant. |
| **Bootstrap community** | The fixed-id IPv8 community (`SeedboxCommunity`) that every node runs to do admission + overlay distribution. |
| **`community_id`** | The 20-byte IPv8 wire prefix that identifies a protocol overlay. For markdown overlays, derived as `sha1(canonical(md))[:20]`. |
| **Compiler LLM** | The OpenAI-compatible model that turns `.md` descriptors into Python `Community` classes. **v5.1 production target**: external GPU-host endpoint via `QWEN_BASE_URL`; **dev/CI fallback**: local Ollama. Distinct from the reasoning LLM. |
| **Donation** | A Bitcoin (testnet) transaction paying the seedbox's wallet address; the proof of admission. |
| **Genesis agent** *(v5.1)* | The agent started with `--genesis <manifest>`: declares a new network by publishing its manifest into `SeedboxCommunity` and serving it via `MANIFEST_REQUEST`. Acts as the admission gatekeeper. |
| **Mission descriptor** *(v5.1)* | One `mission.md` per agent: Identity / Intent / Budget / Stop. The single operator-supplied prose the LLM sees each turn; strict parser refuses recipes. Replaces v5.0's persona + goal pair. |
| **Network manifest** *(v5.1)* | A content-hashed `.md` document describing one network — admission policy (gatekeeper address + min_sats + min_confirmations), genesis peers, default overlays. `network_id = sha1(canonical(md))[:20]`. |
| **Overlay** | An IPv8 community type — historically a Python class, now a markdown document compiled at runtime. |
| **OpenClaw** | The chat host the operator types into. Owns the reasoning LLM. Talks to our MCP server. |
| **MCP** | Model Context Protocol. The streamable-HTTP wire format OpenClaw uses to call our tools. |
| **PEER_INTRO** *(v5.1)* | A SeedboxCommunity wire message auto-sent by both sides of a successful JOIN: carries the sender's wallet address + the set of overlay ids it serves. Receiver stores it in `_peer_meta`. |
| **Reasoning LLM** | The LLM inside OpenClaw's chat host. Picks which tool to call. |
| **Scenario** | A YAML manifest + per-agent `mission.md` files describing how a set of agents should run autonomously. *(v5.1: was persona + goal pair.)* |
| **Seedbox** | A node that publishes one or more overlays and accepts donation-gated admission. |
| **Stop predicate** | A pure function of the state snapshot that the watchdog evaluates before each tick. |
| **Watchdog** | The per-agent polling loop that drives `openclaw agent` subprocesses in a scenario. |

---

## 21. Where this differs from the v4.0 design

| Concept (v4.0) | Replacement (v5.0) |
|---|---|
| `TrustroomCommunity` (custom Community subclass) | Bootstrap is `SeedboxCommunity`; everything else is dynamically compiled from `.md` |
| `AgentChannel` (416-line facade) | `OpenClawAgent` + 13-tool surface; the LLM is the integration layer |
| `StakeOracle` + `StakeOp` + synthetic BTC ledger | Real Bitcoin testnet via `bitcoinlib`; donation is the only admission requirement |
| `TrustStore` + `CredentialFormat` + `VerifiedCredential` | None — admission is "did you pay?" |
| Hand-written `Payload` classes per protocol | `.md` descriptors compiled to `VariablePayload` subclasses at runtime |
| `extra_communities={...}` at IPv8 boot | `ipv8.overlays.append(...)` after start; `OverlayRegistry` owns it |
| FastMCP server exposing 10 frozen trustroom tools | FastMCP server exposing 13 primitives over the new substrate |
| `OpenClawIdentity` (single LibNaCL keyfile) | `AgentIdentity` (BIP-32 multi-key bundle from one BIP-39 seed) |
| Interactive OpenClaw tui as the only operator path | `openclaw tui` still works, plus autonomous scenarios via `make scenario` / watchdog |

The conceptual centre of gravity moved from *"build the right abstractions
in Python"* to *"describe protocols in text the network can carry, and let
agents compile them on arrival."* That is the contribution.

---

## 22. v5.1 delta from v5.0

v5.0 shipped the markdown-as-protocol pivot but kept three properties
the brief actually demanded out of reach:

1. **The agent could not reason zero-shot from its world.** `goal.md` smuggled
   in a seven-step recipe for the seek_cc demo. Bob was following written
   instructions, not deciding.
2. **"The network" was not a first-class artefact.** Every node ran its own
   `SeedboxCommunity` with itself as gatekeeper; joiners learned about peers
   only via operator-driven `peer_add` calls baked into `scenario.yaml`.
3. **The reasoning LLM saw only message *names* per overlay** — no field
   encodings, no handler text. A newly-arrived overlay was opaque, so the
   operator had to pre-bake `overlay_invoke` shapes into the goal.

v5.1 addresses all three. The headline changes:

| Layer | v5.0 | v5.1 |
|---|---|---|
| Network identity | Every agent its own seedbox; no shared artefact | **Network manifest** (`.md`) — content-hashed, gossipped over `MANIFEST_*` wire messages, declared by a genesis agent and consumed by joiners |
| Mission spec | `persona.md` + `goal.md` (operator-encoded recipe) | One `mission.md` per agent: Identity / Intent / Budget / Stop — strict parser rejects backtick-quoted tool names and ≥3-step lists |
| Peer metadata | `peer.mid + address` only | `peer.mid + address + wallet_address + known_overlays`, populated by the auto-`PEER_INTRO` exchange post-admission |
| LLM-visible overlays | `messages: [name…]` | Full per-message field schemas + handler text + errors + dependencies; new `overlay_describe` returns canonical markdown |
| Tools | 13 (peers, wallet, overlays, torrents) | 16 (+ `overlay_describe`, `agent_inject_manifest`, `network_join`) |
| Admission flow | LLM calls `wallet_send` → `seedbox.request_join` manually | `network_join` does parse → peer_add → fetch default overlays → donate → JOIN_REQUEST in one tool call |
| Package layout | `replication/verification/donation_verifier.py` | `admission/donation_verifier.py` |
| Compiler-LLM placement | "Local Ollama on the VPS" (canonical) | **External GPU host via `QWEN_BASE_URL`** (canonical); Ollama is the dev/CI fallback |

What did *not* change: the overlay schema, the AST sandbox, the
`community_id = sha1(canonical(md))[:20]` rule, the BIP-32 identity
layer, the autonomous-scenario harness (`scenario.yaml` + watchdog +
stop predicates + JSONL trace), the BitTorrent service.

**End-to-end consequence for the demo**: Bob's `mission.md` is now
six lines of intent — `# Identity`, `# Intent` ("Acquire a Creative
Commons audio file from the DelftClaw network."), `# Budget`, `# Stop`.
The state snapshot carries Alice's wallet address and overlay
catalogue; the network snapshot carries the admission policy. Bob's
LLM calls `network_join` once (or composes the lower-level tools
itself) and proceeds.

Determinism evidence: `tests/test_compiler_cross_llm.py` compiles
`content_community.md` against two stylistically-divergent stub LLM
outputs (reordered classes, while-loop vs for-loop, renamed locals)
and asserts both yield byte-identical wire format via the compiler's
mandatory test vectors. This is the cheapest empirical check on the
Agora "zero-shot without any ambiguity" claim the project rests on.

Out of scope for v5.1 (deferred): DHT/walker bootstrap, signed manifests,
WASM/seccomp sandbox upgrade, multi-VPS scenarios, mainnet Bitcoin,
cross-stack (TS/Rust) compiler proof-of-concept.

### Post-merge addenda (2026-05-14)

These three changes landed after the v5.1 plan was approved, in
response to operator feedback and the master-branch merge:

1. **Traditional Python `Community` overlays alongside markdown.**
   Colleagues running more complex / static communication experiments
   can register a hand-written `Community` subclass directly via
   `OverlayRegistry.register_community(cls)` (or
   `python -m agent ... --register-community module.path:ClassName`).
   The class must declare its own 20-byte `community_id` and ship its
   `@vp_compile`-decorated `VariablePayload` subclasses in the same
   module; the registry introspects them at registration time.
   **Local-only** — Python bytecode has no canonical transmittable
   form, so these overlays do not flow over the bootstrap community's
   `OVERLAY_*` / `MANIFEST_*` messages. To make a similar protocol
   discoverable across the network, wrap it in a markdown descriptor
   and use the v5.1 path.

   `CompiledOverlay` now carries an `origin: Literal["markdown",
   "python_class"]` discriminator; `parsed` is `Optional` (None for
   the python_class path). `overlays_list` / `state.overlays` emit
   the discriminator + a metadata-light entry for hand-written
   communities; `overlay_describe` returns
   `{"error": "no_canonical_md:python_class"}` for them.

2. **Synthetic wallet replaces the bitcoinlib HD wallet.** The
   merge with master adopted its `dclaw1<hex>`-address synthetic
   `identity.wallet.Wallet`. The deterministic `send(to, sats) -> txid`
   never broadcasts and never queries a service provider. The donation
   gate is preserved on the wire and in the manifest; admission
   verification now defaults to `network="mock"` in
   `admission.donation_verifier.DonationVerifier`, which auto-admits
   any non-empty txid. **Trade-off**: kills the on-chain
   admission verification that was a stated v5.1 goal — but it removes
   the bitcoinlib provider-rotation stalls and faucet-funding pain
   that were blocking the seek_cc demo. The `network="testnet"`
   real-bitcoinlib path is preserved and can be flipped on per-host
   via `BTC_NETWORK=testnet` in `configs/host.env`.

3. **Templated systemd family extended to identity + security MCPs.**
   `delftclaw-identity-mcp@.service` and `delftclaw-security-mcp@.service`
   now mirror the existing `delftclaw-mcp@.service` /
   `delftclaw-watchdog@.service` pattern (run as the `delftclaw`
   system user, read `/etc/delftclaw/instances/<instance>.env`).
   Single bootstrap script (`deploy/setup_vps.sh`) installs all four;
   the colleagues' non-templated gateway + seedbox-audit units stay
   as-is. New `configs/host.env` (gitignored; example at
   `configs/host.env.example`) gives every developer one place to pin
   their Tailscale GPU IP / Qwen endpoint / Bitcoin network.
