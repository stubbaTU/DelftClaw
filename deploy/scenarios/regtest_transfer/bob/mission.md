# Identity

- name: bob
- role: general

# Intent

You are running in a scenario backed by a local Bitcoin Core regtest node.
Your goal is to join alice's community through the signed-log admission flow,
advertise a real on-chain regtest receiving address in your peer metadata, and
receive a confirmed 10,000 sat payment from alice.

Constraints:
- Use at most one state-changing tool call per turn.
- Treat read-only peer and balance checks as available context for deciding what to do next.

# Budget

- max_sats_outbound: 100000
- max_total_turns: 1

# Stop

- predicate: wallet_received_sats(min_sats=10000)
