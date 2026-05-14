# DelftClaw Network Manifest Schema (v1)

This document defines the canonical structure every **network manifest**
(`*_network.md`) must follow. A network manifest is the bootstrap
artefact a joining agent reads to learn (a) who runs the admission
gate, (b) what the admission policy is, (c) which peers can be used to
enter, and (d) which overlay protocols the network speaks by default.

A manifest is **content** in the same sense an overlay descriptor is
content: it is hash-addressable, transmittable over the bootstrap
community, and identified by `network_id = sha1(canonicalize_md(text))[:20]`
where `canonicalize_md` is the function defined in
[`protocol/schema.md`](schema.md) and exported by
`protocol.compiler.canonicalize_md`.

The schema is intentionally rigid. A manifest with two different
interpretations of its admission policy is a broken manifest; every
field has exactly one allowed shape.

## Required sections (in this order)

Every manifest MUST contain these top-level headings, in this order,
with no other top-level headings interleaved.

```
# Identity
# Admission
# Genesis Peers
# Default Overlays
```

Section bodies may contain free text alongside the structured blocks
below. Free text is informative; the parser consumes only the
structured blocks. A section that omits its required structured block
is a schema error.

## `# Identity`

Required key/value list. One per line, formatted `- key: value`.

| Key | Type | Notes |
|---|---|---|
| `name` | snake_case string | Human-readable name (e.g. `delftclaw`). |
| `version` | semver | `<major>.<minor>.<patch>`. |
| `description` | utf-8 string | One-line summary. |

The 20-byte `network_id` is **NOT** written in this section; it is
derived as `sha1(canonicalize_md(text))[:20]`.

## `# Admission`

Required key/value list. One per line, formatted `- key: value`.

| Key | Type | Notes |
|---|---|---|
| `gatekeeper_address` | bech32 string | Bitcoin address joiners donate to. |
| `min_sats` | uint64 | Minimum donation in satoshis. |
| `min_confirmations` | uint16 | Minimum on-chain confirmations before a joiner is admitted. |

The parser enforces:
- `gatekeeper_address` starts with `tb1` (testnet bech32) or `bc1`
  (mainnet bech32). Other prefixes are rejected; the project's BTC
  layer only supports segwit.
- `min_sats >= 1`.
- `min_confirmations` in `[0, 65535]`. Zero is legal (for demos);
  the verifier-side `DonationVerifier.min_confirmations` enforces it.

## `# Genesis Peers`

A 3-column markdown table in exactly this column order:

```
| host | port | pubkey_hex |
|------|------|------------|
| <ipv4 or hostname> | <uint16> | <serialized IPv8 pubkey hex> |
```

At least one row is required. Every row must contain:

- `host` — IPv4 dotted quad or DNS name (no validation of reachability
  at parse time; bad hosts surface at IPv8 add-peer time).
- `port` — uint16 in `[1024, 65535]`.
- `pubkey_hex` — even-length lowercase hex; the parser does not
  validate curve membership, only hex shape.

## `# Default Overlays`

A bulleted list of overlay-descriptor sha1 hashes the network speaks
by default. May be empty.

```
- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a  (content_community v1)
```

Each entry is `- sha1: <40-char lowercase hex>` followed by optional
parenthesised free-text description. The parser keeps the hash and
discards the description.

## Canonicalization rule

The bytes hashed to derive the `network_id` are produced by the same
`canonicalize_md(text)` function defined in `protocol/schema.md`:

1. UTF-8-decode the text.
2. Replace `\r\n` line endings with `\n`.
3. Right-strip trailing whitespace on each line.
4. Remove trailing empty lines.
5. UTF-8-encode the result.

`network_id = sha1(canonicalize_md(text))[:20]`.

## Parse-time guarantees

`protocol.manifest.parse_manifest(text)` enforces, before returning a
`NetworkManifest` to the caller:

1. **Schema validity** — required sections present in order, required
   keys present per section.
2. **Type constraints** — bech32 prefix, sat range, port range, hex
   shape (genesis-peer pubkey, default-overlay sha1).
3. **No duplicate genesis peers** — `(host, port)` pairs must be unique.
4. **No duplicate default overlays** — sha1 hashes must be unique.

If any guarantee fails, `parse_manifest` raises `ManifestParseError`.
Callers (`agent.runtime.OpenClawAgent.load_manifest`, the
`network_join` tool, the `--manifest` / `--genesis` CLI flags) treat
this as a fatal boot error.
