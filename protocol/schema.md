# DelftClaw Overlay Protocol Schema (v1)

This document defines the canonical structure every **overlay descriptor**
(`*_community.md`, `*_overlay.md`, etc.) must follow. The DelftClaw protocol
compiler (`protocol/compiler.py`) parses an overlay-descriptor `.md`,
validates it against this schema, derives a deterministic IPv8
`community_id`, asks an LLM to generate a Python `Community` subclass
that implements the wire format, validates the generated code via an AST
whitelist, and finally exercises the embedded test vectors before the
overlay is allowed to register with the live IPv8 instance.

The schema is intentionally rigid. The Agora paper's "zero-shot without
ambiguity" guarantee is impossible if the same `.md` can be interpreted
two different ways at the byte level — so every field has exactly one
allowed encoding, and every message ships at least two test vectors that
the compiler executes before activating the overlay.

## Required sections (in this order)

Every overlay descriptor MUST contain these top-level headings, in this
order, with no other top-level headings interleaved. Sections marked
`(optional)` may be omitted entirely; when present they MUST appear in
the position shown.

```
# Identity
# Messages
# Runtime State        (optional)
# Constants            (optional)
# Tasks                (optional)
# Errors
# Dependencies
# Test Vectors
```

Sections may contain free text alongside the structured blocks below.
Free text is informative; the compiler only consumes the structured
blocks. Section bodies that omit a required structured block are a
schema error.

## `# Identity`

Required key/value list. One per line, formatted `- key: value`.

| Key | Type | Notes |
|---|---|---|
| `name` | utf-8 string | Human-readable name (e.g. `content_community`). |
| `version` | semver | `<major>.<minor>.<patch>`. |
| `description` | utf-8 string | One-line summary. |
| `lifecycle` | enum (optional) | `peer-observer` (default) or `passive`. |

The 20-byte IPv8 `community_id` is **NOT** written in this section; it is
derived as `sha1(canonical_md_bytes)[:20]`. The compiler computes it and
asserts the generated class declares the same value.

`lifecycle: peer-observer` (default) means the generated class MUST
subclass both `Community` and `PeerObserver`, declare `started()`
calling `self.network.add_peer_observer(self)`, and declare
`on_peer_added(peer)` / `on_peer_removed(peer)` (may be no-ops unless
the descriptor's handler prose specifies behaviour).
`lifecycle: passive` opts out of the `PeerObserver` mixin entirely — for
overlays that have no use for peer-arrival events.

## `# Messages`

For each message, a level-2 heading naming the message in
`SCREAMING_SNAKE_CASE`. Under each message heading:

1. A `msg_id` line: `- msg_id: <uint8>`. Unique within the overlay.
2. A wire-format **table**, in this exact column order:

```
| name | encoding | description |
|------|----------|-------------|
| <field_name> | <encoding> | <free text> |
```

Fields are encoded in table order with no padding. Allowed encodings:

| Encoding | Wire bytes | Python type |
|---|---|---|
| `uint8` | 1 byte | `int` ∈ [0, 255] |
| `uint16-be` | 2 bytes, big-endian | `int` ∈ [0, 2¹⁶) |
| `uint32-be` | 4 bytes, big-endian | `int` ∈ [0, 2³²) |
| `uint64-be` | 8 bytes, big-endian | `int` ∈ [0, 2⁶⁴) |
| `bool` | 1 byte (`0x00` / `0x01`) | `bool` |
| `varlenH` | 2-byte big-endian length, then that many raw bytes | `bytes` |
| `varlenH-utf8` | varlenH whose payload is decoded as utf-8 | `str` |
| `varlenH-msgpack` | varlenH whose payload is `msgpack.packb(value, use_bin_type=True)` | `list`/`dict`/scalar |
| `bytes20` | exactly 20 raw bytes | `bytes` of length 20 |
| `bytes32` | exactly 32 raw bytes | `bytes` of length 32 |

Anything outside this list is a schema error. The compiler maps these
1:1 onto IPv8 ``VariablePayload.format_list`` entries. New encodings can
be added in future schema versions (`v2`, `v3`, …) but require a
compiler upgrade — this is by design: the byte-level surface is small
and audited.

3. A `### Handler` subheading containing free-text operational
semantics: what the receiver does, what side effects are allowed, what
response (if any) is expected. The compiler hands this to the LLM
verbatim as the "what to do on receipt" instructions.

## `# Runtime State` *(optional)*

Public mutable attributes the agent runtime, peers, or tests will
read from or write to on instances of the generated community class.
Declaring them in the descriptor — instead of leaving them implicit
in the handler prose — is what lets two independent LLM compiles
agree on attribute *names* and not just on wire format.

Format: a 3-column markdown table.

```
| name | type | description |
|------|------|-------------|
| local_index    | list[dict] | searchable entries; dicts with keys magnet, name, size, mime, tags |
| response_cache | list[dict] | accumulated peer responses (same dict schema as local_index) |
```

Allowed `type` values are intentionally Python-shaped (the descriptor
is a contract between Python implementations of the same overlay):

| Type | Initialiser the LLM must emit | Notes |
|---|---|---|
| `list[<inner>]` | `self.<name> = []` | Element type is documentation only; the compiler does not type-check element values. |
| `dict[<k>, <v>]` | `self.<name> = {}` | Key/value types are documentation only. |
| `set[<inner>]` | `self.<name> = set()` | |
| `int` | `self.<name> = 0` | |
| `str` | `self.<name> = ""` | |
| `bool` | `self.<name> = False` | |
| `bytes` | `self.<name> = b""` | |

Slot names MUST be snake_case (`[a-z][a-z0-9_]*`). The compiler walks
the generated source's AST and refuses to activate the overlay unless
every listed slot is assigned via `self.<name> = ...` inside
`GeneratedCommunity.__init__`.

This section is optional. Echo-style overlays with no persistent state
omit it. Overlays whose internal state is accessed by the agent runtime
(e.g. `content_community.local_index`) MUST declare every accessed slot
here.

## `# Constants` *(optional)*

Class-level tunables. The agent runtime, tests, or other overlays may
reference these by name; declaring them in the descriptor gives every
LLM compile the same names and values.

Format: a 4-column markdown table.

```
| name | type | value | description |
|------|------|-------|-------------|
| MAX_RESULTS | int  | 50  | maximum entries returned per SEARCH_REQUEST |
```

Allowed `type` values are the same Python-shaped scalars supported by
`# Runtime State`. The `value` cell is parsed as a JSON literal
(`50`, `true`, `"x"`, `[1,2]`).

Constant names MUST be SCREAMING_SNAKE_CASE (`[A-Z][A-Z0-9_]*`). The
compiler reads `getattr(GeneratedCommunity, name)` and refuses to
activate the overlay unless every listed constant exists at class
level with the declared value.

This section is optional.

## `# Tasks` *(optional)*

Periodic background tasks the overlay registers on IPv8's
``TaskManager`` (which ``Community`` already mixes in). Most non-toy
overlays need one — heartbeat exchanges, peer pings, request-cache
sweepers, garbage-collection of stale state. Declaring them in the
descriptor instead of leaving them implicit in handler prose means
two independent LLM compiles produce the same task *names* and
*intervals*, which is what every other layer (state snapshots, tests,
operator tooling) keys off.

Format: a 4-column markdown table.

```
| name | interval_s | handler | description |
|------|------------|---------|-------------|
| heartbeat | 30 | send_heartbeat | broadcast a HEARTBEAT to every verified peer |
| sweep     | 60 | _expire_stale  | drop peer entries not seen in 5×interval |
```

Field rules:

- `name` — snake_case (`[a-z][a-z0-9_]*`); unique within the overlay.
  The compiler verifies this exact string literal appears as the first
  positional argument to a ``self.register_task(...)`` call in
  ``GeneratedCommunity.__init__``.
- `interval_s` — positive integer (seconds between firings). The
  compiler verifies this value appears as the ``interval=<n>``
  keyword argument on the same call. Sub-second tasks are not allowed
  by this schema version — they're rarely useful and almost always a
  symptom of a missing RequestCache.
- `handler` — snake_case method name on the class. The compiler
  verifies the class declares a method with this name. The method
  takes ``self`` only (no other args) and is allowed to be
  ``async def`` or plain ``def``.
- `description` — free text, fed to the LLM verbatim.

Compile-time structural check: for each row, the AST of
``__init__`` must contain a call shaped like
``self.register_task("<name>", self.<handler>, interval=<interval_s>)``.
Other ``register_task`` calls (e.g. one-shot anonymous tasks) are
allowed and ignored; what matters is that every *declared* task has a
matching registration.

This section is optional. Overlays with no periodic behaviour omit it.

## `# Errors`

A table mapping symbolic error names to the policy:

```
| code | name | policy |
|------|------|--------|
| 1 | malformed_payload | drop |
| 2 | not_admitted | reply:JOIN_DENIED |
```

Policies:
- `drop` — silently drop and log.
- `reply:<MSG_NAME>` — respond with the named message (which must exist
  under `# Messages`).

## `# Dependencies`

A bulleted list of other overlay descriptors this one assumes have been
loaded first, identified by their canonical sha1 hash:

```
- sha1: 0123456789abcdef… (seedbox_admission v1)
```

The compiler does not enforce dependency order at compile time — it is
the agent runtime's job (the `OverlayRegistry`) to refuse to register
an overlay whose declared dependencies are not already in the registry.

## `# Test Vectors`

For each message defined under `# Messages`, at least two paired
(structured-fields, hex-bytes) examples. Format:

````
## SEARCH_REQUEST

- fields: { "query": "" }
  bytes: 0000

- fields: { "query": "creative commons" }
  bytes: 0010 6372656174697665 20636f6d6d6f6e73
````

Whitespace inside the `bytes:` value is ignored by the compiler. The
compiler runs both directions — encode the `fields` value and assert
the produced bytes equal the documented `bytes`; decode the `bytes`
value and assert the produced fields equal the documented `fields`.

Test-vector failures abort overlay registration **before** any wire
traffic is sent or received over the new overlay.

## Canonicalization rule

The bytes hashed to derive the `community_id` are produced from the
`.md` text by:

1. UTF-8-decoding the text.
2. Replacing all `\r\n` line endings with `\n`.
3. Right-stripping trailing whitespace on each line.
4. Removing trailing empty lines until the last line is non-empty.
5. UTF-8-encoding the result.

The compiler exposes `protocol.compiler.canonicalize_md(text: str) -> bytes`.

`community_id = sha1(canonicalize_md(md_text))[:20]`.

## Compile-time guarantees

The compiler enforces, before activating an overlay:

1. **Schema validity** — required sections present, encoding allowlist
   respected, `msg_id` uniqueness, error policy targets resolve.
2. **Determinism of `community_id`** — generated source must declare
   `community_id = <bytes from sha1(canonical_md)>`.
3. **AST whitelist** — generated source uses only allowed imports
   (`ipv8.community`, `ipv8.lazy_community`, `ipv8.messaging.lazy_payload`,
   `ipv8.peer`, `ipv8.peerdiscovery.network`); no `eval`/`exec`/`open`/
   `__import__`/`subprocess`/`os.*`/dunder-attribute access.
4. **Test-vector round-trips** — every test vector encodes and decodes
   to the documented values.
5. **Constant declarations** — every entry in `# Constants` exists at
   class level on `GeneratedCommunity` with the declared value.
6. **Runtime-state slots** — every entry in `# Runtime State` is
   assigned via `self.<name> = …` inside `GeneratedCommunity.__init__`.
7. **Lifecycle conformance** — if `lifecycle: peer-observer` (the
   default), `GeneratedCommunity` subclasses `PeerObserver` and
   defines `started`, `on_peer_added`, `on_peer_removed`.
8. **Periodic-task registrations** — every entry in `# Tasks` has a
   matching `self.register_task(name, self.<handler>, interval=<s>)`
   call inside `__init__`, and the named handler method exists.

If any guarantee fails, `compile_overlay()` raises `ProtocolCompileError`
and the agent falls back to natural-language messaging on the bootstrap
community (see Agora's "natural language for rare communications").
