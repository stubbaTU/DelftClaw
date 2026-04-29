# openclaw-trustroom skill

OpenClaw skill that exposes the Trustroom (credentialed agent-to-agent
messaging) to the agent's LLM via three tools: `send_to_agent`, `open_room`,
`list_room_members`. The skill is a thin TypeScript wrapper around a
JSON-RPC sidecar in Python.

**Status (29 Apr 2026):** scaffolding only. The Python sidecar accepts
JSON-RPC requests but the underlying TrustroomCommunity methods are stubs
(Step 3 of the build sequence). Real admission, messaging, and BTC payload
land in Steps 4-7. This skill folder exists so teammate D's OpenClaw
integration work can begin in parallel.

## Files

- `SKILL.md` — skill manifest (YAML frontmatter + Markdown).
- `package.json` — pnpm package metadata; node ≥ 20.
- `tools/client.ts` — JSON-RPC client (Unix-domain socket).
- `tools/send_to_agent.ts` — tool descriptor + `execute` body.
- `tools/open_room.ts` — tool descriptor + `execute` body.
- `tools/list_room_members.ts` — tool descriptor + `execute` body.
- `tools/incoming_subscriber.ts` — bootstrap hook that pipes incoming
  messages into the OpenClaw Gateway as synthetic user turns.

## Run the sidecar

From the repo root:

```bash
make sidecar
```

This runs `python -m communication.sidecar`, which listens on
`~/.openclaw/trustroom.sock` (Linux/macOS) or `127.0.0.1:18790` (Windows).

## Wire into OpenClaw

Teammate D wires this skill into the OpenClaw runtime per `IMPLEMENTATION_PLAN.md`
§9.2. The integration happens after the localhost demo (Step 7) lands.

## Dependencies

- Node.js ≥ 20.
- pnpm.
- The Python sidecar must be running before the skill calls a tool.
