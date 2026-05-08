# Red Team — Trust & Cryptographic Primitives

Lucas's sub-project. Cryptographic primitives that give the Claw Network
tamper-evident audit trails and cross-agent verifiable claims.

## Why these exist

The Claw Network is a fleet of AI agents donating BTC to share seedboxes.
That raises trust questions: which agents have actually donated? Which
seedboxes are real vs faked? How does a third party verify a peer's
report about another agent?

These primitives address that with a layered model:

| Layer | What | Status |
|---|---|---|
| 1 | Hash-chained log (existing `security/subq2_accountability/append_log.py`). Detects in-place edits, but the host could rewrite the whole file. | already there |
| 2 | Every entry Ed25519-signed by the host's identity key. Rewrites now require the private key. | **shipped** (`SignedAppendOnlyLog`) |
| 3 | Peers hold each other's signed claims and serve them to third parties. A's signed advertisements (seedbox offers, identity announcements, receipts) become forwardable evidence. | **shipped** (`witness` entries + HTTP transport) |
| 4 | TrustChain-style pairwise blocks: every A↔B interaction signed by both, written to both chains. (Pouwelse, FGCS 2020.) | not yet |

These primitives defend *integrity* (entry wasn't tampered with; named
signer actually signed it). They do NOT defend *behavior* — a compromised
agent honestly signs whatever its prompt tells it to. Prompt injection
succeeds against a crypto-hardened agent the same as an unhardened one.
That's the "crypto-invisible boundary."

### What witness entries actually capture

A subject only ever signs claims it wants attributed to itself. Witness
entries make A's *own* signed claims portable — B can carry them and
forward to C as proof "A really said this." Realistic claims A will sign:

- "I'm offering a seedbox at host X port Y" (advertisement)
- "I'm announcing my identity: pubkey, identity_hash" (peer discovery)
- "I acknowledge receiving content C from peer P" (delivery receipt)
- "I donated to the network with BTC tx ABC" (donation announcement)

What witness entries do *not* capture: a third party observing A doing
something A wouldn't sign. That kind of observation is recorded as a
*self entry* by the observer (reporter and subject are both the
observer). Misbehavior detection then comes from *combining* a witness
entry (A's claim) with a self entry (someone's observation that the
claim was false): A's signed advertisement + B's signed "I tried it,
hash mismatched" forms a verifiable evidence package that pins the lie
to A.

## What's in here

```
redteam/
├── primitives/
│   ├── signed_log.py    SignedAppendOnlyLog — Ed25519 sign-then-chain
│   │                    wrapper around AppendOnlyLog. Two entry kinds:
│   │                    "self"    A signs its own actions
│   │                    "witness" B records A's signed claim in B's chain
│   ├── peer_log.py      PeerLog — per-source cache of foreign signed
│   │                    entries received from peers. Receiver's own
│   │                    chain stays untouched (cache-only by design).
│   │                    Storage: <peer_log_dir>/<reporter_id>.jsonl
│   └── verify.py        Standalone CLI verifier. Independent — does NOT
│                        import from signed_log (security independence).
└── integration/
    └── server.py        FastAPI on 127.0.0.1:8800. See endpoints below.
```

## HTTP API (loopback only)

```
GET  /health           liveness probe
GET  /identity         { identity_hash, pubkey_hex, network }
GET  /head             { head_hash }                          ("GENESIS" if empty)
GET  /entries          { entries, head_hash }                 ?since=<hash>&limit=<n>
GET  /entries/{hash}   single entry, 404 if absent
POST /log              server signs body and appends to local chain
POST /entries          accept already-signed foreign entry into peer cache
```

`POST /log` — local agent (or OpenClaw via the gateway) records its own
actions. Server signs as the local identity; the caller cannot impersonate
the signer. Minimum body: `{"action": "...", "details": {...}}`.

`POST /entries` — peers push their own signed entries to this agent.
Body is the full v2 entry dict. Server verifies: recomputed `entry_hash`,
Ed25519 signature against `reporter_pubkey`, identity binding
`SHA256(pubkey || network) == reporter_id`, and (for witness entries) the
subject's signature over the claim envelope. Rejects same-identity
submissions and cross-network entries. Idempotent on duplicate
(`stored: false, duplicate: true`, HTTP 200).

## Run a server

```powershell
.venv\Scripts\python.exe -m redteam.integration.server `
    --log signed.log `
    --port 8800 `
    --key-path openclaw_priv.pem `
    --peer-log-dir peer_logs
```

Two instances on one machine: pass distinct `--key-path`, `--port`,
`--log`, `--peer-log-dir`. Loopback bind is enforced.

## Verify a log offline

```powershell
.venv\Scripts\python.exe -m redteam.primitives.verify --log signed.log
```

Exits 0 clean / 1 integrity failure / 2 internal error. Walks every
entry, checks chain links + signatures + identity binding + (for witness
entries) subject signatures.

## Cross-agent demo

End-to-end Alice → Bob round trip: `examples/layer3_demo.py`. Start two
servers on different ports, run the script — it posts entries to Alice,
pulls them via `/entries`, pushes into Bob's peer cache, checks
idempotency, and reads Bob's `<alice_id>.jsonl` to confirm.

## Entry shape (v2)

All entries: `version`, `kind`, `timestamp`, `reporter_id`,
`reporter_pubkey`, `signature`, `entry_hash`, `previous_hash`,
`subject_id`, `action`, `details`, `evidence`, `severity`,
`details_hash`, `evidence_hash`.

Witness entries additionally carry `subject_pubkey`, `subject_claim`,
`subject_signature`. The claim envelope is `{kind:"claim", version,
subject_id, action, details_hash, claim_timestamp, nonce}` — the subject
signs the *envelope* (not the wrapping entry), so one A-signed claim can
ride in N independent witnesses' chains.

Self entries that smuggle `subject_*` fields are rejected as a downgrade
attempt.

## What's not done yet

- **Pull-based sync loop.** No periodic polling between peers; drive sync
  with the demo script or curl. The `agent.py` background sync is a
  separate task.
- **IPv8 production transport.** This is the dev-mode HTTP shim. The
  entry shape and verification logic are transport-agnostic — only the
  wire layer changes when IPv8 is solid.
- **Cross-network peer entries.** Same `NETWORK` only this iteration.
- **Pairwise interaction blocks** (Layer 4 / TrustChain).
- **Witness-of-receipt** (re-recording foreign entries into receiver's
  own chain). Cache-only is intentional; adding receipt-witnessing as a
  flag is additive.
- **Receiver authentication.** Loopback bind is the trust boundary; for
  multi-machine deployments add mTLS or HTTP signatures above this layer.

## Tests

219 tests across `test_signed_log.py`, `test_signed_verify.py`,
`test_peer_log.py`, `test_server_layer3.py`, `test_signed_server.py` (all
at the repo root, not in a `tests/` subdir — existing project
convention). Run:

```powershell
.venv\Scripts\python.exe -m pytest test_signed_log.py test_signed_verify.py `
    test_peer_log.py test_server_layer3.py test_signed_server.py -v
```

New tests for work in this folder should follow `test_<thing>_<expected>`
naming with fresh `tmp_path` per test.
