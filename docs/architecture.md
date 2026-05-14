# DelftClaw — Architecture (As-Built)

**Status:** authoritative as of 2026-05-14. *(v5.2 — community
signed-log treasury, no-treasurer admission, 4-agent seek_cc demo.
See ``PROJECT_DESIGN.md §23`` for the delta from v5.1; §22 for v5.0 → v5.1.)*

**Supersedes:** `PROJECT_DESIGN.md` v5.1 (the canonical reference doc;
this file is a developer-facing distillation. Where they disagree,
`PROJECT_DESIGN.md` wins.)

## 1. Context — what changed

The earlier design centred on a stack of bespoke abstractions
(`TrustroomCommunity`, `AgentChannel`, `StakeOracle`, credential
presentations) layered on top of IPv8. That stack has been removed.
The current system rests on three architectural decisions:

1. **Admission via signed log entry — no treasurer, no key custody
   (v5.2).** A joiner writes a signed `donation_intent` entry to their
   own append-only log. Peers replicate everyone's logs via HTTP pull
   and replay them: membership = the set of donors whose entries pass
   the validation rules (running-average donation cap, no double-join,
   etc.). Treasury balance is the same replay's sum:
   `Σ donation_intent − Σ seedbox_purchase`. There is no gatekeeper
   wallet to defend and no single point of failure.

   *(v5.1 used a real Bitcoin testnet donation to a gatekeeper's
   wallet address; v5.2's signed log replaces that with a synthetic
   wallet + log-replay model. The legacy on-chain path is preserved
   for completeness — set `BTC_NETWORK=testnet` to switch back.)*

2. **Protocol overlays as transmittable markdown.**
   Each IPv8 community type is described in a single `.md` file (its
   wire format, handler semantics, byte-level test vectors). Receiving
   agents fetch that markdown over the wire and compile it into a
   runnable IPv8 `Community` subclass via an LLM, then register the
   result with their live IPv8 instance — **at runtime, without a
   software release**. This follows the agentic meta-protocol direction
   from Agora (arXiv:2410.11905) and ANP.

3. **Seedbox growth as a community decision (v5.2).** When the member
   count exceeds the manifest's `max_agents_per_seedbox × seedbox_count`
   threshold, any admitted member can write a `seedbox_purchase_intent`
   to authorise spawning a new seedbox. First valid intent wins on
   race. Cost matches the manifest's declared `seedbox_cost_sats`
   exactly. A follow-up `seedbox_provisioned` entry closes the intent
   and bumps `seedbox_count`.

Everything below documents what is actually in the code today.

## 2. Layer model

```
┌──────────────────────────────────────────────────────────────────────┐
│  OpenClaw Agent                                                      │
│   - per-node Python process owning every layer below                 │
│   - LLM tool-call loop drives ~12 tools                              │
│   - tools cover peers / wallet / overlays / torrents                 │
├──────────────────────────────────────────────────────────────────────┤
│  OverlayRegistry  │  BitTorrentService  │  BitcoinWallet             │
│   compile + cache  │   libtorrent       │   bitcoinlib HDWallet      │
│   + ipv8 register  │   (stub fallback)  │   at WALLET_PATH           │
├──────────────────────────────────────────────────────────────────────┤
│  ProtocolCompiler                                                    │
│   .md → schema-validate → LLM → AST whitelist → exec → test vectors  │
│       → Type[Community]                                              │
├──────────────────────────────────────────────────────────────────────┤
│  SeedboxCommunity (the only static IPv8 community)                   │
│   JOIN_REQUEST / JOIN_RESPONSE   (donation-gated admission)          │
│   OVERLAY_OFFER / OVERLAY_REQUEST / OVERLAY_DELIVERY                 │
│       (network-as-protocol-distribution)                             │
├──────────────────────────────────────────────────────────────────────┤
│  py-ipv8 (transport, endpoint, prefix routing, signing)              │
│   `ipv8.overlays.append(...)` is the runtime-overlay hook            │
├──────────────────────────────────────────────────────────────────────┤
│  Bitcoin testnet  (bitcoinlib service providers; faucet-fundable)    │
└──────────────────────────────────────────────────────────────────────┘
```

One Python process per node. All layers share memory; no MCP server,
no sidecar.

## 3. Identity and wallet

### 3.1 Seed and derivation

`identity/seed.py` defines a 32-byte `Seed` plus four loaders:
`MnemonicSeedSource` (BIP-39), `EnvSeedSource` (env var, dev-only),
`KeyringSeedSource` (OS keyring), `KeyfileSeedSource` (hex-encoded file
with auto-generation on first run).

`identity/derivation.py` exposes three canonical paths under one BIP-32
chain (`Bip32Ed25519Kholaw`):

| Path | Key | Used by |
|---|---|---|
| `IPV8_PATH  = m/44'/0'/0'/0/0` | Ed25519, wrapped as `LibNaCLSK` | py-ipv8 transport |
| `APP_PATH   = m/44'/0'/0'/1/0` | Ed25519 | application-layer signing |
| `WALLET_PATH = m/44'/0'/0'/2/0` | (unused now — see §3.3) | n/a |

### 3.2 `AgentIdentity`

`identity/agent_identity.py:AgentIdentity.from_seed(seed, network)`
bundles `ipv8` (`IPv8KeyPair`), `app` (`AppSigningKey`), and `wallet`
(`Wallet`). The agent-wide identifier is
`AgentId = sha256(ipv8_raw_pubkey || network)`. Exposed through
`AgentIdentity.network_hash` (`shared.ids.IdentityHash`).

### 3.3 Bitcoin HD wallet

`identity/wallet.py:Wallet.from_seed(seed, btc_network)` is a thin
wrapper over `bitcoinlib.wallets.HDWallet`. The wallet is **keyed by a
secp256k1 master derived directly from `seed.bytes`** via
`bitcoinlib.keys.HDKey.from_seed`, **not** the Ed25519 chain above —
Bitcoin needs secp256k1, and bitcoinlib does its own BIP-32 internally.
The two key chains share the same seed input but produce independent
keys.

Storage: bitcoinlib's SQLite DB at `~/.bitcoinlib/`, wallet-named
deterministically as `delftclaw_<network>_<sha256(seed||network)[:8]>`.

Public surface:
```
wallet.address()             -> bech32 testnet/mainnet address
wallet.balance_sats(refresh) -> int  (refresh=True scans the network)
wallet.send(to, sats)        -> txid hex  (signs + broadcasts)
```

CLI: `python -m identity.wallet --mnemonic '…' {address,balance,send}`.

## 4. SeedboxCommunity — the bootstrap layer

`communication/community.py:SeedboxCommunity` is the **only** statically
loaded IPv8 community. It serves two purposes:

1. Admission: gate new peers behind a verified Bitcoin donation.
2. Overlay distribution: ship protocol descriptors over the wire so
   other communities can be loaded at runtime.

Wire protocol (11 messages — *v5.1: was 5; +2 in Phase 5 for the
no-treasurer admission path*):

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
| 10 | `CommunityJoinRequestPayload` *(Phase 5)* | `signed_entry: varlenH-utf8 (JSON of signed donation_intent)` | joiner → gatekeeper |
| 11 | `CommunityJoinResponsePayload` *(Phase 5)* | `accepted: bool`, `reason: varlenH-utf8` | gatekeeper → joiner |

`community_id = b"openclaw_seedbox_v1\x00"` (exactly 20 bytes). The
manifest trio mirrors the overlay trio bit-for-bit; the separate ids
let a receiver dispatch on intent without parsing the body. The
`PEER_INTRO` message is auto-sent by both sides of a successful JOIN
round-trip and provides the live wallet address + overlay catalogue.

Joiner-side helpers return `asyncio.Future`:

```
request_join(gate, txid)    -> Future[bool]       # JOIN flow
fetch_overlay(peer, hash)   -> Future[bytes]      # OVERLAY flow
publish_overlay(md_text)    -> bytes (md_hash)    # serve via OVERLAY_REQUEST
offer_overlay(peer, hash)   -> None               # advertise
```

Defensive bits: incoming `OVERLAY_DELIVERY` is **re-hashed** before
its waiter is resolved, so a peer can't deliver arbitrary markdown
under someone else's hash. `MAX_OVERLAY_BYTES = 64 KiB` caps a single
descriptor.

## 5. The `.md` overlay system

### 5.1 The schema

`protocol/schema.md` is the meta-meta-protocol: it specifies what every
`*_community.md` / `*_overlay.md` must contain. Five required sections,
in order:

1. **`# Identity`** — `name`, `version`, `description`.
2. **`# Messages`** — for each `## MSG_NAME`: a `msg_id: <uint8>` bullet,
   a wire-format table `name | encoding | description`, and a
   `### Handler` free-text block describing operational semantics.
   Allowed encodings (enforced by the compiler):
   `uint8`, `uint16-be`, `uint32-be`, `uint64-be`, `bool`,
   `varlenH` (2-byte big-endian length-prefixed bytes),
   `varlenH-utf8`, `varlenH-msgpack`, `bytes20`, `bytes32`.
3. **`# Errors`** — code/name/policy table.
4. **`# Dependencies`** — sha1 hashes of other `.md`s this overlay
   assumes are loaded first.
5. **`# Test Vectors`** — ≥2 `(fields_json, bytes_hex)` pairs per
   message. **Mandatory** — they are how the compiler proves the
   generated code is wire-compatible.

The 20-byte IPv8 `community_id` is **not** written by hand; it's
derived as `sha1(canonical_md_bytes)[:20]`. Canonicalisation: strip
trailing whitespace per line, collapse `\r\n` to `\n`, drop trailing
empty lines, UTF-8 encode.

### 5.2 The compiler pipeline

`protocol/compiler.py:compile_overlay(md_text, llm) -> CompiledOverlay`:

```
md_text
  → parse_md(md_text)            structured ParsedOverlay
  → validate_schema(parsed)      encoding allowlist, msg_id uniqueness,
                                 cross-section refs
  → canonicalize_md(md_text)
  → community_id = sha1(canonical)[:20]
  → user_prompt = _build_user_prompt(parsed, community_id)
  → source = llm.complete(SYSTEM_PROMPT, user_prompt)
  → strip_code_fences(source)
  → safe_exec(source)            AST whitelist + namespaced exec
  → assert generated class declares the same community_id
  → run_test_vectors(payload_classes, parsed.test_vectors)
  → CompiledOverlay(community_id, parsed, source, community_class,
                    payload_classes, ...)
```

Anything that fails raises `ProtocolCompileError`. The result is a
fully-formed `Type[Community]` ready for IPv8 to load.

The LLM behind it is pluggable via the `LLMClient` Protocol
(`protocol/llm.py`):

- `OpenAICompatibleClient(base_url, model_id, api_key)` — talks to any
  OpenAI-compatible `/v1/chat/completions` endpoint (vLLM / TGI /
  llama.cpp). The supervisor-provided GPU host is the production
  target.
- `StubLLMClient(sources={community_id_hex: python_source})` — keyed
  by community_id, used by tests + the `--compiler-stub` CLI mode.

### 5.3 The sandbox

`protocol/sandbox.py:validate_ast(source)` + `safe_exec(source)`:

Allowed imports (anything else → `SandboxError`):
`ipv8.community`, `ipv8.lazy_community`,
`ipv8.messaging.lazy_payload`, `ipv8.peer`,
`ipv8.peerdiscovery.network`, `msgpack`, `struct`.

Forbidden inside the generated module:
`eval`, `exec`, `compile`, `open`, `__import__`, `globals`, `locals`,
`vars`, `delattr`, `setattr`, `getattr`, `input`, `breakpoint`,
`with`/`async with` blocks, `global`/`nonlocal`, and any access to
`__class__`, `__bases__`, `__subclasses__`, `__mro__`, `__globals__`,
`__builtins__`, `__dict__`, `__init_subclass__`, `__import__`,
`__loader__`, `__spec__`.

Compiled overlays run in the same process. The trust gradient is
small because **the only peers who can ship overlays at all have
already paid donation-admission to the seedbox**, but the AST walk
still rejects the obvious foot-guns. For a future production
deployment, this is the sandboxing layer to upgrade
(subprocess+seccomp, WASM, …).

### 5.4 Runtime registration

`protocol/registry.py:OverlayRegistry` exposes **two** registration paths:

```python
reg = OverlayRegistry(ipv8, llm_client)

# Markdown path (v5.1 default): compile a descriptor via LLM, register
# the generated class. Idempotent on community_id.
overlay_instance = reg.load(md_text)

# Python-class path (post-merge): register a hand-written Community
# subclass directly. No markdown, no LLM. Idempotent on community_id.
overlay_instance = reg.register_community(MyCommunity)
```

Both paths build `CommunitySettings(my_peer, endpoint, network)` from
any already-loaded overlay, instantiate the class,
`ipv8.overlays.append(instance)` under `ipv8.overlay_lock`, call
`instance.started()`. IPv8 routes incoming UDP packets to the new
community automatically — `Community.__init__` registers a 22-byte
prefix listener on the shared endpoint
(`ipv8/messaging/interfaces/endpoint.py:_prefix_map`).

The two paths cache into the same `_compiled[cid] / _instances[cid]`
dictionaries; `CompiledOverlay.origin` discriminates them
(`"markdown"` vs `"python_class"`). The python_class path is
**local-only** — there is no canonical text representation of a Python
class, so these overlays are not gossipped via OVERLAY_* messages.

No IPv8 monkey-patching. No restart.

### 5.5 Configuration: how an overlay actually gets onto a node

There are now three concrete entry points by which a node can learn
about and start running a protocol overlay. The first two are
operator-driven; the third is the network-driven path that the whole
design hinges on.

**(a) Boot-time publish — `--publish-overlay PATH`** (operator-driven).
The CLI reads the file, computes `community_id = sha1(canonical_md)[:20]`,
calls `OpenClawAgent.publish_overlay(md_text)` which both **serves** it
(adds to `SeedboxCommunity._published` so peers can fetch it) **and**
locally compiles + registers it (so this node also speaks the protocol).
This is how a seedbox declares "I serve `content_community.md`".

**(b) In-LLM tool call — `overlay_publish(md_text)`** (agent-driven, same
effect as (a) but at runtime). The LLM can decide to ship a new
protocol if it has the markdown in hand.

**(c) Network arrival — the zero-shot path.** A peer offers an overlay
via `OVERLAY_OFFER(md_hash)`. The receiving agent (or its LLM) calls
`overlay_fetch_and_load(peer_mid, md_hash)`, which sends
`OVERLAY_REQUEST`, awaits `OVERLAY_DELIVERY`, **re-hashes the delivered
bytes to verify they match the requested hash**, and then runs the same
`OverlayRegistry.load(md_text)` pipeline as (a) and (b). No human
intervention; no software release.

What ties all three together: every path funnels through
`compile_overlay(md_text, llm) -> CompiledOverlay`, then through
`ipv8.overlays.append(instance)` under the IPv8 lock. The
`community_id` is a content hash, so two nodes that loaded the same
descriptor — whether from disk, from a tool call, or from the wire —
are on the same overlay by construction.

### 5.6 Why markdown-as-protocol vs. the traditional approach

The "traditional way" for an IPv8 system is: every protocol is a
hand-written `Community` subclass, payloads are `@vp_compile`-decorated
`VariablePayload` classes in source, the IPv8 boot config registers
them via `extra_communities={"FooCommunity": FooCommunity}`. That is
what the deleted trustroom layer did, and what most py-ipv8 example
projects do today. We do **not** do it that way for the
content/search/admission overlays (only the bootstrap
`SeedboxCommunity` remains static).

**Traditional, static communities — pros**

- **Type-safe at edit time.** Mypy, the IDE, and reviewers see the
  full protocol definition. Linting works normally.
- **Reviewable in one place.** A Community is one Python file; you
  can read it top-to-bottom without indirection.
- **Deterministic by construction.** Bit-for-bit identical wire format
  across every node because every node ran the same import. No
  generation step to disagree on.
- **No LLM dependency.** Works on an air-gapped machine; works during a
  GPU host outage; works in CI.
- **Zero cold-start.** First connection to a known protocol pays no
  generation cost.
- **Trivial sandbox.** You wrote and reviewed the code; "trust" is the
  same as for any other module you imported.
- **Mature debugging.** Stack traces point at lines in your repo;
  breakpoints, profilers, coverage tools all just work.

**Traditional, static communities — cons**

- **A new protocol is a software release.** `git push`, `pip install`,
  restart every peer that wants to speak it. Out-of-band coordination
  every time the spec changes.
- **Two peers can only meet on protocols both already have on disk.**
  The network cannot carry its own extensibility — it carries content,
  not protocols.
- **`community_id` is hand-picked.** No automatic collision protection
  in a heterogeneous network; versioning is implicit
  (`b"openclaw_seedbox_v1\x00"` is a literal, not a derivation).
- **Cross-stack interop costs reimplementation.** A Rust or TypeScript
  agent needs the protocol spec re-translated into its own type system
  for every message — there is no portable artifact.
- **The wire format and the prose description drift.** README says one
  thing, `format_list = ["varlenH"]` says another, comments are stale.
  No single source of truth.
- **No path for an autonomous agent to discover a new protocol.** A
  zero-shot LLM agent can't adopt a protocol it has never imported,
  even if a peer is happy to describe it.

**Markdown descriptor + runtime compile — pros**

- **Protocol is content.** A `.md` is hash-addressable, transmittable,
  cacheable, gossipable. The network can carry its own extensibility.
- **Zero-shot adoption.** An agent that has never seen overlay X can
  receive `X.md` from a peer, compile, register, and be speaking X in
  one round-trip — no software release, no human in the loop.
- **Versioning is intrinsic.** `community_id = sha1(canonical_md)[:20]`.
  Two nodes that share a hash are byte-compatible by construction.
  Different versions get different ids automatically.
- **Cross-stack portability for free.** Any agent runtime that
  implements the same compiler pipeline (Python, TS, Rust, ...) can
  speak the same overlay against any other implementation. The text
  is the source of truth.
- **One artifact, one truth.** The `.md` is simultaneously the human
  documentation, the wire-format spec, the handler semantics, and the
  test corpus. They can't drift.
- **Test vectors are mandatory.** Every message must ship ≥2 hex
  examples that the compiler executes before activation. This is a
  stronger correctness criterion than "the tests in the repo pass".
- **Composability via reference.** A descriptor can declare it depends
  on `sha1: 0123…` (another descriptor); the registry can refuse to
  activate until the dependency is loaded.

**Markdown descriptor + runtime compile — cons**

- **LLM non-determinism is the central risk.** Two LLMs (or one LLM
  across versions) reading the same `.md` might generate
  wire-incompatible code if the schema lets them. Mitigated — not
  eliminated — by strict encoding allowlist + mandatory test vectors
  that gate activation. A bad LLM run fails closed; it doesn't
  produce silently-wrong wire bytes.
- **LLM cold-start cost.** First contact with a new overlay pays a
  generation round-trip (typically 1-3s with a local model). Cached by
  `sha1(canonical_md) || model_id || model_version`, so steady-state
  cost is zero, but the worst case matters.
- **Hard dependency on a reachable LLM endpoint.** If your model is
  unreachable you can still speak overlays you've already cached, but
  you cannot adopt new ones. Recovery is "wait for the LLM" or "fall
  back to natural-language messaging" — Agora's "natural language for
  rare communications" path.
- **Trust boundary expands.** Incoming markdown can trigger local code
  generation. The AST whitelist (`protocol/sandbox.py`) blocks the
  obvious foot-guns (`eval`/`exec`/`open`/`__import__`/dunders/etc.),
  and the donation-admission gate restricts who can ship descriptors
  in the first place, but prompt-injection of the LLM via the
  descriptor body is a new attack surface.
- **Debugging spans three artefacts.** A wire-level disagreement could
  live in the `.md` schema, the LLM-generated source, or the compiler
  glue. Test vectors localise the symptom (encode mismatch on message
  X) but not always the cause.
- **Tooling is weaker on the prose side.** The encoding tables are
  parseable and validated; the handler-semantics free-text isn't.
  Subtle handler-behaviour disagreements only surface when peers
  actually interoperate.
- **Performance ceiling.** Generation-via-LLM is the slowest part of
  the system. Acceptable for control-plane operations (joining a new
  overlay), prohibitive for data-plane (per-message dispatch is
  unaffected — runtime dispatch is the same as a hand-written
  community).

**When each approach fits**

| Use case | Pick |
|---|---|
| Stable, well-known, security-critical protocol (e.g. the admission gate) | Traditional. `SeedboxCommunity` stays hand-written. |
| Experimental protocols, content overlays, application-specific extensions | Markdown descriptors. New protocols cost text, not a release. |
| Heterogeneous agent runtimes that need to interoperate | Markdown descriptors — text is the only portable contract. |
| Air-gapped deployments with no LLM | Traditional. Or pre-compile every descriptor offline and ship the cache. |
| Research artefact where the protocol *is* the experiment | Markdown descriptors. The `.md` is the experimental subject. |

The architectural bet is that for an agentic P2P network — where
peers are LLM-driven, where new content types appear constantly, and
where heterogeneous runtimes will eventually need to interoperate —
the *current* cons (cold-start latency, non-determinism risk, trust
boundary) are tractable engineering problems, while the *traditional*
cons (every protocol is a software release, no in-network
extensibility) are architectural ceilings. This is the same bet Agora
and ANP make.

## 6. First concrete overlay — `content_community`

`protocol/examples/content_community.md` is the canonical example +
the smoke target for SEARCH:

```
SEARCH_REQUEST  (msg_id=1):  query: varlenH-utf8
SEARCH_RESPONSE (msg_id=2):  results: varlenH-msgpack[list[dict]]
```

Handler semantics (in the markdown's prose, fed into the LLM prompt):
case-insensitive substring match against `name` + joined `tags`; cap
at 50 results; empty query returns the full index. Reference
implementation in `protocol/examples/content_community_stub.py`
(`CONTENT_COMMUNITY_SOURCE`).

`community_id = sha1(canonical_md)[:20] =
a3455e9cec3b78bc281f1c495b0a08baa733833a`.

## 7. BitTorrent

`communication/bittorrent.py` defines the `BitTorrentService` Protocol:

```
service.add_magnet(magnet_uri) -> Future[Path]
service.seed(path)             -> magnet_uri str
service.stats()                -> list[TorrentInfo]
service.stop()
```

Two implementations, picked by `build_default_service(save_dir)`:

- `LibTorrentService` — real `libtorrent.session`, lazy-imported, used
  when libtorrent is installed.
- `StubBitTorrentService` — in-process fake. `seed(path)` stores `path`
  keyed by a deterministic magnet URI; `add_magnet(uri)` resolves
  immediately to that path (or a placeholder for unknown URIs). Used
  by the test suite and by every dev environment that doesn't have
  the native binding.

## 8. The agent runtime

### 8.1 `OpenClawAgent`

`agent/runtime.py:OpenClawAgent` owns everything that boots per node:

```
AgentIdentity        BitcoinWallet         IPv8
SeedboxCommunity     BitTorrentService    OverlayRegistry
LLMClient
```

Lifecycle: `await agent.start()` builds the IPv8 instance + loads the
bootstrap community + wires a `DonationVerifier` pointing at the
agent's own wallet address as the seedbox. `await agent.stop()` tears
all of it down.

Helpers:
```
agent.add_peer(host, port, pubkey_hex)   # pre-introduce a peer at boot
agent.publish_overlay(md_text)           # serve + locally load
agent.known_peers()                      # union across all overlays
```

### 8.2 Tool surface for the LLM

`agent/tools.py:build_tools(agent)` builds a `ToolRegistry` of 23
functions the LLM can call (*v5.2: +7 over v5.1; v5.1 was 16; v5.0 was 12*):

| Tool | Effect |
|---|---|
| `peers_list` | list peers verified on any overlay |
| `peer_add` *(v5.1)* | pre-introduce a peer at runtime |
| `wallet_address` / `wallet_balance` / `wallet_send` | wallet ops (synthetic in `BTC_NETWORK=mock`) |
| `seedbox_donate_and_join` | **DEPRECATED** in v5.2 — legacy single-gatekeeper path |
| `community_donate_and_join` *(v5.2)* | sign + append a `donation_intent` to own log; debits the wallet |
| `community_join_via_peer` *(v5.2)* | end-to-end wire path — appends locally then ships to a gatekeeper peer over msg_id 10/11 |
| `community_treasury_balance` *(v5.2)* | balance, member count, seedbox count, threshold status |
| `community_member_count` *(v5.2)* | slim view: count + own membership status + threshold |
| `community_log_list_recent` *(v5.2)* | merged log view (own + every peer's chain) with accepted/rejected flags |
| `seedbox_purchase_propose` *(v5.2)* | sign + append a `seedbox_purchase_intent`; first-comer wins |
| `seedbox_provisioned` *(v5.2)* | sign + append a `seedbox_provisioned` entry closing a pending intent (mock-spawn for now) |
| `overlays_list` | full per-message field schemas + handler text + errors + dependencies |
| `overlay_describe` *(v5.1)* | canonical markdown of a loaded overlay (32 KiB cap) |
| `overlay_fetch_and_load` | OVERLAY_REQUEST from a peer → compile → register |
| `overlay_publish` | serve a `.md` over OVERLAY_REQUEST |
| `overlay_invoke` | generic dispatcher: send a message on any compiled overlay |
| `agent_inject_manifest` *(v5.1)* | parse + cache a network manifest; pre-introduces genesis peers |
| `network_join` *(v5.1)* | end-to-end admission: manifest → peer_add → fetch overlays → donate → JOIN_REQUEST |
| `torrent_seed` / `torrent_fetch` / `torrent_stats` | libtorrent surface |

`overlay_invoke` closes the protocol-extensibility loop: once the
registry has a compiled class, the LLM can call any message in it by
name without the runtime having ever statically known about that
protocol. The seven v5.2 tools close the community-accounting loop:
the LLM can read treasury + member state and write donation /
purchase / provisioned entries entirely through MCP, with no
gatekeeper key custody anywhere in the system.

### 8.3 LLM tool-call loop

`agent/loop.py:run_tool_loop(user_query, llm, tools, *, system_prompt,
max_iterations=10)`. Conventional OpenAI-style loop:

```
messages = [system, user]
loop:
    response = llm.complete_with_tools(messages, tools.specs())
    messages.append(assistant_message)
    if no tool_calls:
        return assistant_text
    for each tool_call:
        result = await tools.dispatch(name, args)
        messages.append({role: "tool", tool_call_id, name, content})
```

`OpenAICompatibleToolLLM` for production, `StubToolLoopLLM(responses)`
for tests + offline development.

### 8.4 CLI

`python -m agent` exposes three subcommands; see `agent/cli.py`
docstring for the full reference. Three boot-time flags drive
per-agent configuration:

```
--publish-overlay PATH    repeatable; load + serve a .md at boot
--peer HOST:PORT:PUBKEY    repeatable; pre-introduce a peer
--system-prompt PATH       override the default LLM persona
```

`info` prints the agent's `peer_introduce_line` so a sibling can paste
it as `--peer` and skip walker/bootstrap entirely.

## 9. End-to-end flows

### 9.1 Donation-gated admission

```
Joiner (Alice)                          Gatekeeper (Bob)
   |                                            |
   |  Wallet.send(bob_addr, 10000 sats)         |
   |---broadcast txid to bitcoin testnet------->|  (out-of-band)
   |                                            |
   |  request_join(bob, txid)                   |
   |---JOIN_REQUEST(txid)---------------------->|
   |                                            |
   |                                   DonationVerifier
   |                                   .verify(txid):
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

### 9.2 Overlay discovery + compile + register

```
Publisher (Alice)                       Consumer (Bob)
   |                                       |
   publish_overlay(content_md)             |
   md_hash = sha1(canonical)[:20]          |
   _published[md_hash] = content_md        |
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

### 9.3 Content SEARCH (the demo target)

```
Alice has:                              Bob wants files.
   - SeedboxCommunity (bootstrap)          - SeedboxCommunity
   - content_community (loaded)            - knows Alice is a peer
   - local_index = [creative-commons-...]
                                                       |
User: "what files are on our claw network?"            |
                                                       |
                                  LLM tool loop:       |
                                  1. peers_list -> [alice]
                                  2. (does Bob know content_community? no)
                                     overlay_fetch_and_load(alice, ?)
                                     (above sequence runs)
                                  3. overlay_invoke(
                                       community_id, SEARCH_REQUEST,
                                       peer=alice, fields={query: "..."})
                                                       |
                                  content_community.ez_send(alice, payload)
                                                       |
                                              SEARCH_REQUEST(query) ---
                                                                       |
   on_search_request(alice_local, payload):                            |
     scan local_index, build results                                   |
     ez_send(bob, SEARCH_RESPONSE(msgpack(results)))                   |
                                                                       |
                                                  SEARCH_RESPONSE     |
                                  on_search_response:                  |
                                    response_cache.extend(results)     |
                                                       |
                                  4. (loop produces final assistant text)
                                                       |
                                  User sees: "<list of matching files>"
```

## 10. Determinism, trust, and risks

| Risk | Mitigation in code |
|---|---|
| Two LLMs reading the same `.md` produce different wire bytes | Strict encoding allowlist; `community_id` derived from the `.md` (not LLM-chosen); every message ships ≥2 test vectors that the compiler runs before activation |
| Malicious `.md` → arbitrary Python execution | AST whitelist (imports, builtins, dunders, `with`); donation-admission gate restricts who can ship overlays; 64 KiB size cap |
| Peer ships markdown that mismatches the hash it claims | `on_overlay_delivery` re-canonicalises + re-hashes before resolving the waiter; mismatched delivery is silently dropped |
| Compile non-determinism across model versions | Cache key includes the model id + version; same `(canonical(md), model_id, version)` is reused |
| libtorrent missing | `build_default_service` falls back to `StubBitTorrentService`; tests use it unconditionally |
| Bitcoin testnet service outage | `DonationVerifier` returns a typed `DonationVerification(accepted=False, reason="fetch_failed:...")`; caller can retry or refuse |
| Malformed `.md` arrives | `compile_overlay` raises `ProtocolCompileError`; agent's LLM-layer fallback is plain-text on the bootstrap community (Agora's "natural language for rare comms") |

## 11. Repository layout

```
identity/                  # seed → BIP-32 → ipv8 / app / wallet keys
  seed.py                  # Seed + 4 SeedSources
  derivation.py            # IPV8_PATH / APP_PATH / WALLET_PATH
  ipv8_key.py              # LibNaCLSK from derived bytes
  app_key.py               # Ed25519 from derived bytes
  wallet.py                # bitcoinlib HDWallet; CLI: `python -m identity.wallet`
  agent_identity.py        # the multi-key bundle

communication/
  community.py             # SeedboxCommunity (the only static community)
  bittorrent.py            # BitTorrentService Protocol + Stub + LibTorrent impls

protocol/                  # the .md overlay system
  schema.md                # canonical descriptor format
  compiler.py              # parse → validate → LLM → AST → exec → test vectors
  llm.py                   # LLMClient Protocol; OpenAICompat + Stub
  sandbox.py               # AST whitelist + namespaced safe_exec
  registry.py              # OverlayRegistry — runtime ipv8 registration
  examples/
    echo_overlay.md             # smallest possible round-trip overlay
    echo_overlay_stub.py
    content_community.md        # the SEARCH overlay
    content_community_stub.py

admission/                # v5.1: was replication/verification/
  donation_verifier.py     # bitcoinlib-backed txid → DonationVerification

agent/                     # the per-node process
  runtime.py               # OpenClawAgent (start/stop, owns every layer)
  tools.py                 # the 12 LLM-callable tools
  loop.py                  # async tool-call loop; OpenAICompat + Stub LLMs
  cli.py                   # `python -m agent {info,run,serve}`

examples/
  ipv8_hello/run_two_peers.py    # pre-existing minimal IPv8 demo (still works)
  donation_demo.py               # admission round-trip (mock + live modes)
  overlay_demo.py                # echo descriptor ships + compiles end-to-end
  run_two_agents.py              # two real `python -m agent` processes

tests/                     # 36 in-tree pytest cases
  test_protocol_compiler.py      # 16 — schema, sandbox, end-to-end compile
  test_overlay_registry.py       # 7  — publish/fetch/hash, idempotent register
  test_content_community.py      # 3  — SEARCH round-trip
  test_bittorrent.py             # 5  — stub seed/fetch, default fallback
  test_agent_runtime.py          # 5  — agent lifecycle + tool loop SEARCH
# plus 132 signed-log tests in the redteam suite (test_signed_log.py etc.)
```

## 12. Testing playbook

Four layers, fastest to most involved:

1. **Automated suite, ~45s, no network.**
   `python -m pytest tests/test_protocol_compiler.py tests/test_overlay_registry.py tests/test_content_community.py tests/test_bittorrent.py tests/test_agent_runtime.py test_signed_log.py test_signed_verify.py test_peer_log.py`
   → expect **168 passed**.

2. **Two-process demo, ~30s, no network.**
   `python -m examples.run_two_agents`
   → ends with `"Asked Alice; the SEARCH_REQUEST was sent on the
   content community."`

3. **Per-component CLI smoke** — `identity.wallet`, `examples.donation_demo
   --mock-verifier`, `examples.overlay_demo`, `python -m agent ... info`.

4. **Live runs** — supervisor's LLM endpoint (no `--compiler-stub` /
   `--llm-stub-script`) and Bitcoin testnet faucet
   (`examples.donation_demo --min-confirmations 1`).

## 13. Autonomous multi-tenant scenarios

The interactive `openclaw tui` path treats the agent on the VPS as a tool
host driven by a human operator. The autonomous path adds a watchdog
that drives an `openclaw agent` subprocess in a polling loop, so multiple
OpenClaw agents on the same VPS communicate without keyboard input. The
operator only observes (via `journalctl` + JSONL logs).

### Per-VPS process layout

```
ollama.service                                   (shared compiler LLM)

delftclaw-mcp@<scenario>-<agent>.service         (one per agent)
    EnvironmentFile=/etc/delftclaw/instances/<scenario>-<agent>.env
    runs `python -m agent ... mcp` bound to the agent's IPv8 + MCP ports

delftclaw-watchdog@<scenario>-<agent>.service    (one per agent)
    same EnvironmentFile
    runs `python -m deploy.watchdog` — the polling loop
```

Bringing a scenario up is one command from the operator's laptop:

```bash
make scenario NAME=seek_cc      # rsync + python -m deploy.scenario_boot seek_cc
make watch    NAME=seek_cc      # journalctl -fu 'delftclaw-{mcp,watchdog}@seek_cc-*'
make stop     NAME=seek_cc      # python -m deploy.scenario_boot seek_cc --teardown
make scenarios                  # list running scenarios + agents
```

### Scenario manifest (`deploy/scenarios/<name>/scenario.yaml`)

Strict schema, validated at parse time by `deploy/scenario.py`:

| Field | What |
|---|---|
| `name` | Scenario id (used in systemd instance names: `<scenario>-<agent>`) |
| `watchdog.interval_s` | Seconds between watchdog ticks |
| `watchdog.max_iterations_per_turn` | Tool-call cap inside one `openclaw agent` subprocess |
| `watchdog.max_total_turns` | Per-agent tick cap |
| `watchdog.max_wall_clock_s` | Scenario-wide hard timeout |
| `agents.<name>.ipv8_port` / `mcp_port` | UDP / TCP ports allocated to this agent |
| `agents.<name>.publish_overlays` | `.md` descriptors served at boot via the bootstrap community |
| `agents.<name>.mission_file` *(v5.1)* | Single `mission.md` the watchdog feeds the LLM each turn. Replaces v5.0's `persona_file` + `goal_file` split; legacy keys raise a migration error. |
| `agents.<name>.stop_predicate` | Named predicate from `deploy/stop_predicates.py` |
| `agents.<name>.peers` | Other agents this one is cross-introduced to at scenario boot |
| `agents.<name>.seed_content` | Optional list of `{magnet, name, size, mime, tags}` pre-loaded into the agent's `content_community.local_index` |

The parser rejects: missing keys, unknown predicate names, peer
references to unknown agents, self-peering, port collisions, ports
outside `[1024, 65535]`, missing overlay paths, missing mission file,
mission whose `# Intent` smuggles in a recipe.

### Stop predicates (`deploy/stop_predicates.py`)

Resolved by name from the scenario YAML. The watchdog evaluates the
predicate before each tick; **the LLM never decides it's done**, the
watchdog does.

| Name | Triggers when |
|---|---|
| `never` | always False (long-running seedboxes) |
| `torrent_progress_gte_1` | any `torrent_stats` entry reports `progress >= 1.0` |
| `peer_count_gte_N(n=…)` | `peers_list` returns ≥ N peers |
| `wallet_received_sats(min_sats=…)` | balance has increased ≥ N sats vs scenario start |

Predicates are pure functions of the snapshot dict. No I/O inside them.

### Watchdog turn protocol (`deploy/watchdog.py`)

Each tick:

```
1. snapshot = collect_state(agent)      # peers, overlays, wallet, torrents
2. predicate(snapshot)  → exit 0 if True
3. turn_n >= max_total_turns  → exit 1
4. elapsed >= max_wall_clock_s → exit 2
5. prompt = mission_text + json(snapshot) + history_tail(3)   # v5.1
6. subprocess: openclaw agent --agent <instance> --message <prompt> --json
7. log JSONL line {turn_n, prompt, response, snapshot, stop_value}
8. sleep tick_remaining
```

Exit codes are meaningful: 0 (predicate hit), 1 (turn cap), 2 (wall
clock), 3 (N consecutive `openclaw agent` failures). systemd records
the reason; `Restart=no` so they aren't silently re-launched.

### Strict guarantees

1. Every turn's prompt is built deterministically from
   {mission.md, snapshot, history tail}. No hidden human input. *(v5.1)*
2. Three caps are enforced before the prompt is built. The LLM cannot
   make the scenario run forever.
3. Stop conditions are named predicates in code; manifests reference
   them by name only.
4. Each agent gets its own systemd instance, env file, state dir
   (`/var/lib/delftclaw/<scenario>/<agent>/`), seed file, MCP port,
   IPv8 port, and JSONL log file.
5. `make scenario` is idempotent — re-running cleanly restarts.
6. Every turn writes one JSONL line; the run is replayable from log
   alone.

### First concrete scenario: `seek_cc`

`deploy/scenarios/seek_cc/scenario.yaml` defines two agents:

- **Alice** publishes `protocol/examples/content_community.md`, seeds
  one Creative Commons audio entry into the index, never stops.
- **Bob** is cross-introduced to Alice via `peer_add` at boot, donates,
  fetches the content community, runs SEARCH, downloads the magnet,
  exits via `torrent_progress_gte_1`.

End-to-end demo:

```
make scenario NAME=seek_cc      # ~10 min, ~6 GB peak RAM
make watch    NAME=seek_cc      # tail until Bob's watchdog exits 0
```

## 14. Where this differs from the old design

| Concept (old) | Replacement (current) |
|---|---|
| `TrustroomCommunity` | Bootstrap layer is `SeedboxCommunity`; everything else is dynamically loaded via `.md` |
| `AgentChannel` (416-line facade) | `OpenClawAgent` + tool surface; the LLM is the integration layer |
| `StakeOracle` / `StakeOp` / synthetic BTC | Real Bitcoin testnet via `bitcoinlib`; donation is the only admission requirement |
| `TrustStore` / `CredentialFormat` / `VerifiedCredential` | None; admission is "did you pay?" |
| Hardcoded `Payload` classes per protocol | `.md` descriptors compiled to `VariablePayload` subclasses at runtime |
| `extra_communities={...}` at IPv8 boot | `ipv8.overlays.append(...)` after start; `OverlayRegistry` owns it |
| FastMCP server exposing 10 frozen tools | In-process Python tool surface called directly by the LLM loop |
| `OpenClawIdentity` (single LibNaCL keyfile) | `AgentIdentity` (BIP-32 multi-key bundle from one BIP-39 seed) |

The conceptual centre of gravity moved from "build the right
abstractions in Python" to "describe protocols in text the network
can carry, and let agents compile them on arrival." That is the
contribution.
