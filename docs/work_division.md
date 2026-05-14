# Work division — 5-person CSE3000 team

5 students, each owning one TU Delft sub-project. The v5.1 codebase
collapsed some of the original folder boundaries; this file documents
the *current* lane→folder mapping.

## Lane → folder mapping

| Sub-project | Owner | Primary folder(s) | Notes |
|---|---|---|---|
| 1. Identity | teammate A | `identity/` | BIP-32 multi-key bundle, KeyfileSeedSource, MCP identity server (`identity/mcp_server.py`). Used by every other lane. |
| 2. **Communication** | **me (Nikola)** | `communication/`, `protocol/`, `admission/`, `agent/`, `deploy/` | The markdown-as-protocol substrate + autonomous scenarios. The headline. |
| 3. Security | teammate B | `security/` (whole subtree), `redteam/primitives/` | SubQ1 (Brain-vs-Hands), SubQ2 (signed append-only log + reputation), SubQ3 (gVisor + sandbox readiness). |
| 4. Trust | (merged into Security under v5.1) | — | The v4.0 standalone `trust/` package was withdrawn 2026-05-08 with the supervisor's consent; donation-anchored evidence and the signed log replaced credential-based trust. |
| 5. Self-Replication | teammate C | `replication/` | Child-agent provisioning + sporestack adapter; consumes `admission/` for cross-network admission flow. |

## My scope (Communication) — what's in the v5.1 codebase

- `communication/community.py` — `SeedboxCommunity`, the only static IPv8
  community: donation-gated admission + overlay/manifest gossip + PEER_INTRO.
- `communication/bittorrent.py` — `BitTorrentService` Protocol with
  `LibTorrentService` and `StubBitTorrentService` impls.
- `protocol/` — the markdown-as-overlay system:
  `schema.md` (descriptor format), `compiler.py` (parse → LLM → AST →
  test-vector pipeline), `sandbox.py`, `registry.py`, `manifest.py`.
- `admission/donation_verifier.py` — bitcoinlib-backed txid → DonationVerification.
- `agent/` — `OpenClawAgent`, 16-tool MCP surface, FastMCP server.
- `deploy/` — autonomous multi-tenant scenarios: `scenario_boot.py`,
  `watchdog.py`, `mission.py`, `stop_predicates.py`,
  `delftclaw-mcp@.service` + `delftclaw-watchdog@.service` templates.
- `shared/` — pure typed primitives (`AgentId`, `IdentityHash`).

## What disappeared in the v4.0 → v5.1 pivot (2026-05-08)

- `TrustroomCommunity` + five hand-written message types — replaced by
  `SeedboxCommunity` + markdown overlays compiled at runtime.
- `AgentChannel` (416-line facade) — replaced by `OpenClawAgent` + the
  MCP tool surface; the LLM is the integration layer.
- `StakeOracle` / `StakeOp` / synthetic-BTC ledger — replaced by real
  Bitcoin testnet via `bitcoinlib`; donation IS the only admission requirement.
- `TrustStore`, `CredentialFormat`, `VerifiedCredential`, `W3CJWTFormat` —
  removed entirely.
- `skills/openclaw-trustroom/` (TypeScript adapter) — removed.
- `communication/{transport,channel,messaging,trustroom,payload,wire}/`
  subpackages — collapsed into `communication/community.py` +
  `communication/bittorrent.py`.

## Cross-lane coupling that still matters

- **Identity → everyone.** `AgentIdentity.from_seed(seed, network)` is
  the entry point. `agent_id = sha256(ipv8_raw_pubkey || network)` is
  the project-wide identifier; nobody else may redefine it.
- **Communication → Security.** `security/integration/` still consumes
  `communication/claw/openclaw_agent.py` (the legacy PoC community kept
  for the colleague's gateway tests). Touching those files crosses lanes;
  go through the Security owner.
- **Communication → Replication.** `admission/donation_verifier.py` is
  consumed by Replication for cross-network admission flow.

## Coordination rules

- `shared/` types are frozen — they appear in every lane's signatures.
- Each lane owns its tests under `tests/`.
- The colleagues' `security/integration/*` MCP gateway is out of scope
  for the v5.1 Communication thesis but coexists in the repo. Don't
  break those tests when refactoring shared/.
