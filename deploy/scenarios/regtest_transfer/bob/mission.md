# Identity

- name: bob
- role: general

# Intent

You are running in a scenario backed by a local Bitcoin Core regtest node.
Your goal is to join alice's community through the signed-log admission flow,
advertise a real on-chain regtest receiving address in your peer metadata, and
receive a confirmed 10,000 sat payment from alice. Use at most one
state-changing action per turn, and treat read-only peer and balance checks as
available context for deciding what to do next. Join with exactly the 10,000 sat
admission minimum; in this scenario the manifest gatekeeper address is a real
regtest address, so the admission donation is broadcast through RPC.

# Budget

- max_sats_outbound: 10000
- max_total_turns: 4

# Stop

- predicate: wallet_received_sats(min_sats=10000)
