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
order, with no other top-level headings interleaved.

```
# Identity
# Messages
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

The 20-byte IPv8 `community_id` is **NOT** written in this section; it is
derived as `sha1(canonical_md_bytes)[:20]`. The compiler computes it and
asserts the generated class declares the same value.

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

If any guarantee fails, `compile_overlay()` raises `ProtocolCompileError`
and the agent falls back to natural-language messaging on the bootstrap
community (see Agora's "natural language for rare communications").
