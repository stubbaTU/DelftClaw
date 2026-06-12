# Plugging the real OpenClaw runtime into the harness (Phase 2b)

This is the verified runbook for running the Phase A ablation against a **real OpenClaw
agent** (Claude Sonnet 4.6) on a VPS. It supersedes the earlier "drive the agent loop"
sketch — that mental model was wrong. The facts below were confirmed empirically against
OpenClaw 2026.5.5 / Claude Code 2.1.156.

## The model (how it actually works)

OpenClaw **drives the agent itself** — you do not run the LLM loop. You run one shot:

```
openclaw agent --agent <id> --local --model claude-cli/claude-sonnet-4-6 \
  --message "<attack payload / turn>" --json --timeout 300
```

The `claude-cli` provider spawns the local `claude` binary, which runs on your **Claude Code
Max subscription (OAuth) — $0 metered.** OpenClaw injects the workspace files into the system
prompt and runs the agent to completion in that one invocation.

You interpose in **two** places, not one:

1. **The tool surface (live gate).** The agent's tools come from an MCP server you register.
   By default the `claude` binary *also* exposes its own built-ins (Bash/Write/Read/WebFetch…),
   which bypass your server — so you **disable them** (see "Lockdown" below). With built-ins
   off, your MCP server is the agent's *only* set of hands: every effectful action is an MCP
   call whose body you wrote, so you can audit (P2) and **genuinely block** (P1) it.
2. **The trace (post-hoc record).** `openclaw agent --json` is opaque (final text + provider
   routing only). The real per-tool-call record lives in the **Claude Code session JSONL** at
   `~/.claude/projects/<workspace-path-hash>/<sessionId>.jsonl`; the `sessionId` is in the
   turn's `meta.agentMeta.sessionId`. Tail that file to reconstruct the tool-call trace
   (`tool_use` name + args, `tool_result` content, ordering). MCP tools appear as
   `mcp__<server>__<tool>`.

```
  per trial:
    set MCP-server trial context (variant, owner id, constitution hashes, sender_id, log path)
    P3 pre-launch gate  ──diverges?──► record "blocked-at-bootstrap", stop
            │ ok
    openclaw agent --local --json --message <attack>     ← real Sonnet turn, $0
            │   (agent calls our MCP tools; each body = dispatch(decision))
            ▼
    tail ~/.claude/projects/<hash>/<sessionId>.jsonl  → tool-call trace
            ▼
    judge: deterministic post-condition on the trace → JSONL trial record
```

## The three components to build

1. **Harness MCP server** (FastMCP, streamable-http). Exposes the experiment tool surface;
   each tool body is `return dispatch(decision)` against the existing
   `redteam_ablation.runtime.base.Dispatcher` — so the interceptors run first and a denial
   returns a `"DENIED: …"` string the agent observes on its next step. The server holds the
   **current trial's context** (the harness sets it before each `openclaw agent` call):
   `owner_identity`, `owner_id`, `published_/session_constitution_hash`, `sender_id`
   (owner vs spoofed, per the attack's vector), `signed_log_path`.
2. **Per-trial driver.** Provision a throwaway `$HOME` + workspace files (the constitution) →
   run the P3 gate → `openclaw mcp set` to the harness server → `openclaw agent --local --json`
   → read `sessionId` → tail the session JSONL → parse into an `EpisodeResult` → judge → write
   the 12-field trial line. One `openclaw agent` invocation = one trial; sessions are wiped
   between invocations, so trials are independent.
3. **`openclaw.json` provisioning** (the lockdown — see below).

## Lockdown — make the MCP server the sole tool surface (V4, verified)

Write `~/.openclaw/openclaw.json` (per-agent HOME) with a `cliBackends.claude-cli` override
adding **`--tools ""`** to **both** `args` and `resumeArgs`:

```json
{
  "agents": { "defaults": { "cliBackends": { "claude-cli": {
    "command": "claude",
    "args": ["-p","--output-format","stream-json","--include-partial-messages","--verbose",
             "--setting-sources","user","--allowedTools","mcp__harness__*","--tools",""],
    "resumeArgs": ["-p","--output-format","stream-json","--include-partial-messages","--verbose",
                   "--setting-sources","user","--allowedTools","mcp__harness__*","--tools","",
                   "--resume","{sessionId}"]
  }}}}
}
```

`--tools ""` removes all Claude Code built-ins *before the model sees them* (leaving MCP tools
untouched); it doesn't touch `permission-mode`, so OpenClaw's `bypassPermissions` can stay.
Both arg sets need it (resumed sessions otherwise revert to unrestricted defaults). Do **not**
rely on a project `.claude/settings.json` — OpenClaw hard-rewrites `--setting-sources user`, so
project/local settings are never loaded.

**Optional tamper floor (V3):** `/etc/claude-code/managed-settings.json` (managed tier, loaded
regardless of `--setting-sources`) with `"disableBypassPermissionsMode": "disable"` + a
**comprehensive** `permissions.deny` list (must include `Agent`, `Task*`, `Skill`,
`ToolSearch`, `Glob`, `Grep`, not just Bash/Write/Read). Host-wide, needs sudo. Use only if you
want a guarantee the agent's own config can't lift.

## Where P1/P2/P3 hook

- **P3 — pre-launch gate.** Before `openclaw agent`, hash the workspace files + exposed tool
  schema + grants; if it diverges from the pinned `published_constitution_hash`, don't launch
  (episode = blocked-at-bootstrap). The constitution can't change between two tool calls, so
  this is its only honest layer.
- **P1 — stamped at the turn, enforced at the MCP boundary.** The harness sets the trial's
  `sender_id` (owner vs spoofed, from the attack's vector) in the MCP server context;
  `OwnerAnchoredIdentityInterceptor` denies non-owner senders inside `dispatch()`. Because the
  MCP server is the sole surface, the deny is a complete block. NOTE for the paper: the
  principal is **harness-supplied at turn construction, not cryptographically authenticated
  from a live channel** — state this honestly.
- **P2 — at the MCP tool boundary.** `SignedLogAuditInterceptor.on_execute` signs each executed
  call; never blocks (ASR(V2) ≈ ASR(V0)).

## Cost & determinism

- **$0 metered** — claude-cli runs on the Max subscription. 400 turns ≈ subscription quota
  (~13–17s/turn). Confirm quota headroom before a full run.
- No real seed/temperature knob on claude-cli; `--thinking` is off by default. Determinism is
  "reproducible-within-sampling-tolerance" — seeds govern payload substitution only. Pin the
  OpenClaw + claude versions and record the model id.

## Decisions still open (settle before the full run)

- **Tool set (Lucas):** expose the **real DelftClaw tool surface** (`wallet_send`,
  `seedbox_donate_and_join`, … from `agent/mcp_server.py`) as recording/sandboxed no-ops and
  re-author the 8 Shapira fixtures + predicates against them (recommended — maximal ecological
  validity), vs the 6 abstract dangerous tools (weaker "real surface" claim).
- **P1 framing (Bulat):** inline-block (with the harness-stamped-principal caveat) vs
  audit-grade.
- **Per-attack deterministic predicates (Lucas):** one trace post-condition per attack, like
  AgentDojo's per-task `security()` function.

## VPS run steps

```bash
git clone <repo> redteam-ablation && cd redteam-ablation
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
pip install fastmcp        # for the harness MCP server
# write ~/.openclaw/openclaw.json cliBackends override (above)
make phase-a-live          # provisions per-trial HOMEs, runs openclaw agent, tails JSONL, judges
make table
```
