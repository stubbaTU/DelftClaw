# Work division — 5-person team

5 people, each owning one TU Delft sub-project. Folder boundaries equal team
boundaries (ADR 0001).

## Lane → folder mapping

| Sub-project (PDF) | Owner | Folder(s) |
|---|---|---|
| 1. Identity | teammate A | `identity/` |
| 2. **Communication** | **me (Nikola)** | `communication/` + slice of `shared/`, `integration/`, `skills/openclaw-trustroom/` |
| 3. Security | teammate ? | likely `integration/` (sidecar hardening, container isolation, prompt-injection harness) — confirm at next team sync |
| 4. Trust | teammate B | `trust/` |
| 5. Self-Replication | teammate C | `replication/` |

## My scope (Communication)

- All seven sub-packages under `communication/`:
  `transport/`, `trustroom/`, `admission/`, `messaging/`, `payload/`, `wire/`,
  `channel/`
- Owner of `shared/envelopes.py` (`WireFrame`, `ApplicationMessage`,
  `BTCPayload`). Other lanes consume these but should not edit them without
  my sign-off.
- Owner of `skills/openclaw-trustroom/` (TypeScript) plus the matching
  `integration/rpc/schema.py` + `integration/tools/*` — these are the tool
  surface the LLM sees, so they belong to whoever owns the channel.

## Joint work per the PDF (all 5, week 1)

- **"Basic UDP networking"** — already settled by ADR 0002 (consume py-ipv8).
  Joint task is just agreeing on `NetworkConfig` and bootstrap peers. ~1 day.
- **"BIP-32 HD wallet"** — lives in Identity's folder
  (`identity/derivation.py` + `identity/wallet.py` + `identity/agent_identity.py`)
  but the canonical derivation paths (`IPV8_PATH`, `MLS_PATH`, `BTC_PATH`,
  `REPLICA_PATH_TEMPLATE`) need 5-way sign-off — they appear in my wallet,
  MLS keys, and Replication's child seeds.

## Critical-path order — who unblocks whom

1. **Identity** ships `Seed` + `AgentIdentity` (week 1–2). Until then nobody
   can instantiate anything.
2. **Me** — wire `transport/` + a stub `TrustroomCommunity` that runs over
   IPv8 with no VC and no MLS. This is the "two agents on localhost
   exchanging plaintext" milestone the docx calls out.
3. **Trust** ships `W3CJWTFormat` + `LocalFileTrustStore` (week 2–3). Then
   I light up `admission/`.
4. **Me** — implement `messaging/ratchet_session.py` (Path B per ADR 0003).
   Pure-Python, no external dep, doesn't block on the MLS-vs-ratchet
   decision.
5. **Me + Identity** — wire `payload/bitcoin_payment.py` against
   `Wallet.compose_payment` (week 3–4).
6. **Replication** + **Security** run in parallel from week 3. Both consume
   `AgentIdentity` and my `AgentChannel` but don't gate my deliverables.

## Coordination rules

- `shared/` types frozen by end of week 1. Any change after that needs all 5
  people to ack — those types appear in everyone's signatures.
- Each person owns their package's `pyproject.toml` and tests. Cross-package
  edits go through a PR that the affected owner reviews.
- `[tool.uv.sources]` workspace deps already wired; nobody should need to
  touch root packaging.

## Open question for the team

Repo has `integration/` but no `security/` folder. Confirm whether the
Security teammate owns `integration/`, shares it with me, or plans a new
package. That decision changes whether the JSON-RPC sidecar / tool layer is
mine or theirs.
