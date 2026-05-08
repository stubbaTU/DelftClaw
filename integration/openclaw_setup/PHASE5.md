# Phase 5 — Two autonomous OpenClaw agents

This is the M3 deliverable: two LLM-driven agents complete the full M2 flow
(room admission, signed messaging, sat transfer) end-to-end with **no human
prompting beyond a single system message each**.

If Phase 4 passed at all (even step-by-step), the wire layer is proven.
Phase 5 is a model-quality test: can your local LLM autonomously chain 5-7
tool calls when given the goal up front?

## Topology

One Linux user, two terminal sessions, two `openclaw chat` instances.

```
┌──────────────────── this machine ────────────────────┐
│                                                       │
│  Terminal 1: orchestrator                             │
│    boots both MCP servers, creates the room,          │
│    prints both system prompts, holds open             │
│                                                       │
│  Terminal 2: openclaw chat  ── delftclaw-alice ──┐    │
│    paste ALICE system prompt → runs autonomously │    │
│                                                  ▼    │
│                                      ┌──────────────┐ │
│                                      │ Alice MCP    │ │
│                                      │ :8081 IPv8 9091
│                                      └──────────────┘ │
│                                              ▲        │
│  Terminal 3: openclaw chat  ── delftclaw-bob ┼─┐      │
│    paste BOB system prompt → runs autonomously │ │    │
│                                                ▼ │    │
│                                      ┌─────────────┐  │
│                                      │ Bob MCP     │  │
│                                      │ :8082 IPv8 9092
│                                      └─────────────┘  │
└───────────────────────────────────────────────────────┘
```

Both MCP servers run from the orchestrator process; the two `openclaw chat`
sessions are independent and could be in tmux panes or separate terminals.

## Prerequisites

- Phase 0 (bench `ping`) and Phase 4 (single LLM Bob, even if step-by-step)
  both worked. If not, fix those first.
- Ollama running with at least one tool-calling-capable model loaded.
  Recommended for autonomous chaining: `hermes3:8b`, `llama3.1:8b`,
  `mistral-small:22b`. Avoid `qwen2.5:7b` — it could not complete autonomous
  6-step chains in our testing.
- The `bench/delftclaw-bench` registration from Phase 0 can stay; harmless.

## Step 1 — Register both MCP servers in OpenClaw

```bash
openclaw config set mcp.servers.delftclaw-alice \
  '{"url":"http://127.0.0.1:8081/mcp","transport":"streamable-http"}'

openclaw config set mcp.servers.delftclaw-bob \
  '{"url":"http://127.0.0.1:8082/mcp","transport":"streamable-http"}'

openclaw mcp list
# Expected: shows delftclaw-bench, delftclaw-alice, delftclaw-bob.
# Both alice and bob should expose 10 delftclaw_* tools each.
```

You can leave both registered permanently — the orchestrator boots and tears
down the corresponding servers as needed.

## Step 2 — Pick the model

```bash
# Quick recommendations, in order of "smallest that should work autonomously":
ollama pull hermes3:8b        # ~5 GB, tool-use specialised
# or
ollama pull llama3.1:8b       # ~5 GB, strong general tool use
# or
ollama pull mistral-small:22b # ~13 GB, biggest that fits in your RAM budget
```

Then point OpenClaw at it (use whichever config key your version supports —
verify via `openclaw config get`). Quick smoke check before launching the
orchestrator:

```bash
openclaw chat
# In the chat: "Call delftclaw-alice__delftclaw_whoami and tell me the agent_id."
# Expected: model emits a real tool call; OpenClaw returns alice's agent_id.
```

If that single-tool call works, the model can talk to both servers. If it
silently produces nothing, the model is too weak — try a different one before
proceeding.

## Step 3 — Start the orchestrator

In **Terminal 1**:

```bash
cd "/home/nikola-emilov/Documents/Netherlands/TU Delft/Courses/CSE Year 3/Q4/CSE3000 Research Project/DelftClaw"
. venv/bin/activate
python -m integration.mcp_server.phase5_orchestrator
```

It will:

- run `setup_demo` (mints issuer keypair, derives both agent identities,
  writes `peers.yaml`, issues Bob's `dev-vc`),
- boot Alice's MCP server on :8081 / IPv8 :9091,
- boot Bob's MCP server on :8082 / IPv8 :9092,
- programmatically create a stake-gated room via Alice's MCP (so the
  room_id is deterministic and printable),
- print **two system prompts** (one for Alice, one for Bob) with the
  room_id baked in,
- save those prompts to:
  - `integration/configs/phase5_room.txt`
  - `integration/configs/phase5_alice_prompt.txt`
  - `integration/configs/phase5_bob_prompt.txt`

Leave it running.

## Step 4 — Launch Alice's autonomous agent

In **Terminal 2**:

```bash
openclaw chat
```

Paste the entire ALICE system prompt the orchestrator printed (or pipe it):

```bash
# Or non-interactively if your OpenClaw supports stdin piping:
cat "integration/configs/phase5_alice_prompt.txt" | openclaw chat
```

The Alice agent will:

1. Loop on `delftclaw_recv_message` waiting for Bob's greeting.
2. Reply once with `"hello back, bob"`.
3. Stop.

## Step 5 — Launch Bob's autonomous agent

In **Terminal 3**:

```bash
openclaw chat
```

Paste the BOB system prompt. Bob will autonomously:

1. Lock 1000 sats for admission.
2. Join Alice's room with `dev-vc` + the stake_proof.
3. Send `"hello from bob"`.
4. Receive Alice's reply.
5. Transfer 200 sats to Alice.
6. Report his final balance.

Both agents run in parallel — Alice's loop can already be polling while Bob
is mid-lock. They synchronize naturally via IPv8.

## Step 6 — Verify it worked

In **Terminal 1** (orchestrator), or any other shell:

```bash
# Bob's side: he should have hit lock, join, send, recv, transfer, balance
grep -E "stake_lock_attempt|join_attempt|join_succeeded|send_attempt|recv_returned|stake_transferred" \
  logs/mcp_bob_phase5.stdout.log

# Alice's side: she should have admitted Bob, received his message, replied
grep -E "on_join_request_admitted|on_application_message_delivered|send_attempt|application_sent" \
  logs/mcp_alice_phase5.stdout.log
```

Expected final balances (the canonical check):

- Bob:   spendable=3800, locked={admission:room=<room_id>: 1000}
- Alice: spendable=5200 (her 5000 faucet + 200 from Bob)

You can check via either agent's MCP `delftclaw_wallet_balance` tool, or by
asking the LLM for the report.

## Step 7 — Shut down

`Ctrl-C` in Terminal 1. The orchestrator sends `SIGINT` to both MCP server
subprocesses, which release their UDP and TCP ports cleanly.

## Pass / fail criteria

**PASS** (M3 done):

- Both LLM agents complete their goals autonomously after a single
  system-prompt paste each.
- Bob's MCP log contains the full `lock_attempt → join_succeeded → send →
  recv → transfer → balance` sequence.
- Alice's MCP log contains `on_join_request_admitted → application_received
  → send_attempt`.
- Final balances reconcile to 3800/5200.

**SOFT FAIL** (model-side, fixable):

- Bob's LLM stalls after step 2 because it can't pass the structured
  `stake_proof` through unchanged → upgrade the model (mistral-small:22b
  handles structured pass-through reliably; many 7-8B models don't).
- Alice's LLM exits after one empty `recv_message` instead of looping →
  the prompt's "Keep calling until non-null" line isn't strong enough;
  reinforce with explicit count, e.g. "call up to 30 times".
- Either LLM narrates JSON instead of emitting tool calls → model is too
  weak; swap.

**HARD FAIL** (transport-side, would block the writeup):

- `delftclaw_lock_for_admission` errors with anything referencing IPv8,
  Peer, or KeyError → check `mcp_bob_phase5.stdout.log` for the exception.
  This was working in Phase 4 so a regression here is unlikely.

## Notes

- The orchestrator does not run a scripted reply on either side — both
  agents are pure LLM. If you want the Phase-4-style "Python Alice + LLM
  Bob" again, use `phase4_alice_host.py` instead.
- Both MCP servers reuse the same `~/.openclaw-alice/` and `~/.openclaw-bob/`
  workspaces between phases; no need to re-run setup between Phase 4 and 5.
- The room_id changes every orchestrator restart (UUID-fresh). The system
  prompt files (`phase5_*_prompt.txt`) are rewritten each run with the
  current id.
