---
name: openclaw-trustroom
description: |
  Send and receive credentialed, end-to-end-encrypted messages between
  autonomous OpenClaw agents on different machines. Use for agent-to-agent
  coordination where authentication, integrity, or value transfer matter.
tools:
  - send_to_agent
  - open_room
  - join_room
  - list_room_members
  - present_credential
  - send_payment
---

# Trustroom communication skill

This skill connects your agent to the Trustroom network layer. The Trustroom
provides:

- VC-gated admission: only credentialed peers can join a room.
- Forward-secret group messaging: past traffic stays confidential even if
  long-term keys leak.
- Authenticated value transfer: Bitcoin payloads travel inside encrypted
  envelopes with their own signatures.

## When to use

Use `send_to_agent` when the user asks you to coordinate with another agent
(by name or by capability) and the request involves sensitive data, value
transfer, or actions that require credentialed authentication.

Do NOT use this skill for:

- Communication with humans (use the channel-specific skills instead).
- Anonymous or pseudonymous interactions (use Tor or another overlay).
- Communication with non-OpenClaw services (use HTTP or MCP instead).

## Tool signatures

(Implemented in `src/tools/`. The Python sidecar at `~/.openclaw/trustroom.sock`
must be running. If it is not, fail loudly and instruct the user to run
`make sidecar` from the repo root.)

### send_to_agent

Sends a message (optionally bundled with a Bitcoin payment) to a Trustroom.

### open_room

Creates a new room with a policy specifying which issuers and claims are
acceptable for joining peers.

### join_room

Joins an advertised room by presenting a stored Verifiable Credential.
Returns whether admission was granted.

### list_room_members

Returns the current set of credentialed peers in a room.

### present_credential

Builds a holder-bound Verifiable Presentation tied to a specific audience and
nonce, for use in admission flows that need an explicit presentation step.

### send_payment

Composes, signs, and broadcasts a Bitcoin payment to another agent. Returns
the on-network transaction id.
