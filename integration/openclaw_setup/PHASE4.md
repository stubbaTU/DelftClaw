# Phase 4 — One real OpenClaw + MockAgent (Alice as scripted host)

This is the first phase that involves a real LLM. You drive **Bob** through
an OpenClaw chat session; **Alice** is a Python-driven host that prepares
a room, waits for Bob's message, and replies once.

If Phase 0–3 passed, the wire layer is proven. Phase 4 is verifying that
a real LLM correctly sequences our 10 `delftclaw_*` tools end-to-end. If
it can't, the workaround is usually a stronger model (qwen2.5:14b → 7b
fallback or vice versa) or a sharper system prompt.

## Prerequisites

* Phase 0 already passed (you saw the bench `ping` round-trip in OpenClaw).
* OpenClaw 2026.5.6 or compatible installed; Ollama running with at least
  one tool-calling model.
* `bench/delftclaw-bench` registered in OpenClaw config (you can leave it
  in place — having multiple MCP servers registered is fine).

## Step 1 — Clean state on the OpenClaw side

The bench server registration from Phase 0 is harmless to keep. We're
**adding** a new server entry, not replacing.

```bash
# Sanity check the current MCP servers OpenClaw sees
openclaw mcp list
# Expected to show at least 'delftclaw-bench' from Phase 0
```

## Step 2 — Register Bob's MCP server with OpenClaw

The Phase 4 driver will boot Bob's MCP server on `127.0.0.1:8082`. Tell
OpenClaw about it:

```bash
openclaw config set mcp.servers.delftclaw-bob \
  '{"url":"http://127.0.0.1:8082/mcp","transport":"streamable-http"}'

openclaw mcp list
# Expected: shows both 'delftclaw-bench' and 'delftclaw-bob'.
```

## Step 3 — Start the host driver

In one terminal:

```bash
cd "/home/nikola-emilov/Documents/Netherlands/TU Delft/Courses/CSE Year 3/Q4/CSE3000 Research Project/DelftClaw"
. venv/bin/activate
python -m integration.mcp_server.phase4_alice_host
```

The driver will:

* Re-derive Alice's and Bob's identities (idempotent),
* Mint a fresh issuer keypair and re-issue Bob's `dev-vc`,
* Boot Alice's MCP server on `:8081` and Bob's on `:8082`,
* Connect to Alice's MCP, create a stake-gated room, and **print a
  ready-to-paste prompt** for the OpenClaw chat session.

You'll see something like:

```
╔════════════════════════════════════════════════════════════════════╗
║                  M3 PHASE-4 OPENCLAW DEMO READY                    ║
║  Alice (host)   → http://127.0.0.1:8081/mcp   IPv8 :9091           ║
║  Bob   (joiner) → http://127.0.0.1:8082/mcp   IPv8 :9092           ║
╚════════════════════════════════════════════════════════════════════╝

Now switch to your OpenClaw chat session and tell the agent:

─────────────────────────── PROMPT ───────────────────────────
You are 'bob'. Use the delftclaw tools.

1. Lock 1000 sats for admission to room <ROOM_ID>, host_alias 'alice'.
2. Join that room with vc_id 'dev-vc', host_alias 'alice', using the
   stake_proof you just got back.
3. Send the message 'hello from bob' to target_alias 'alice' in that room.
4. Poll delftclaw_recv_message until you receive a reply.
5. Transfer 200 sats to recipient_alias 'alice'.
6. Report your final wallet balance.
──────────────────────────────────────────────────────────────

  Room id:           <abc...>
  Issuer pubkey hex: <ed25519 pubkey hex>
  Alice agent_id:    <base32>

Alice is waiting for an inbound message and will reply once.
```

Leave the host driver running.

## Step 4 — Drive Bob through OpenClaw chat

In a second terminal:

```bash
openclaw chat
```

Once the TUI is up, paste the prompt the host driver printed (everything
between the dashed lines, with the real room id substituted). The LLM
should now:

1. Call `delftclaw_lock_for_admission` → get a `stake_proof` back.
2. Call `delftclaw_join_room` with the `stake_proof` → `ok=True`.
3. Call `delftclaw_send_message` to alice.
4. Call `delftclaw_recv_message` repeatedly until alice's reply arrives.
5. Call `delftclaw_transfer` for 200 sats to alice.
6. Call `delftclaw_wallet_balance` and report.

Expected final output from the LLM (roughly):

> Joined room <id>. Sent "hello from bob" to alice. Alice replied
> "hello back, bob". Transferred 200 sats to alice. Final balance:
> 3800 spendable, 1000 locked under admission:room=<id>.

Alice's terminal should show:

```
[alice] received: 'hello from bob' from <bob's agent_id>
[alice] replied: 'hello back, bob' (message_id=...)
```

## Step 5 — Ctrl-C to shut down

Stop the host driver with Ctrl-C. It will clean up both MCP server
subprocesses and release the IPv8 UDP ports.

## Pass / fail criteria

**Pass (proceed to Phase 5):**

* The LLM completes all 6 prompt steps without manual intervention.
* Alice's terminal logs the inbound + outbound messages.
* Bob's MCP server log (`logs/mcp_bob_phase4.stdout.log`) shows real
  tool calls hitting `AgentChannel`.
* Final balances reconcile: bob = 3800 spendable + 1000 locked, alice
  = 5200 spendable.

**Soft fail (LLM-side, fixable):**

* LLM gets stuck in a `recv_message` loop without ever sending or
  transferring → tighten the prompt or upgrade the model
  (`openclaw config set model.default ollama/qwen2.5:14b`).
* LLM passes wrong types / forgets `host_alias` → it's typically a
  smaller model issue (3B-class). Try a 7B+ model.
* LLM hallucinates an `agent_id` instead of using `host_alias` → call
  `delftclaw_list_peers` first in the prompt to ground it.

**Hard fail (transport-side, would block Phase 5):**

* `delftclaw_lock_for_admission` returns an error referencing IPv8 /
  Peer / KeyError → the bench check passed but somehow our peer
  resolution broke. Check `logs/mcp_bob_phase4.stdout.log` for the
  exception.

## Cleanup

* `Ctrl-C` the host driver.
* Optional, to remove the OpenClaw MCP entry:
  `openclaw config unset mcp.servers.delftclaw-bob` (if available;
  otherwise edit `~/.openclaw/openclaw.json` directly).

Phase 5 reuses the same workspace, so you don't need to re-run
`setup_demo` between Phase 4 and Phase 5.
