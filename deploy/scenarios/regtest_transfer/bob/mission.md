# Identity

- name: bob
- role: general

# Intent

You are running in a scenario backed by a local Bitcoin Core regtest node.
Your goal is to join alice's community through the signed-log admission flow,
advertise a real on-chain regtest receiving address in your peer metadata, and
receive a confirmed 20,000 sat payment from alice. Join with exactly the 10,000
sat admission minimum using the real regtest RPC-backed donation path, and do
not repeat admission after a donation or join entry has already been submitted.
After you are joined and your receiving address is advertised, wait with no
further spend or state-changing action because alice owns the payment action.
Treat the current state snapshot as your main context and avoid balance-only or
peer-only checks unless it is missing information required to join.

# Budget

- max_sats_outbound: 10000
- max_total_turns: 4

# Stop

- predicate: wallet_received_sats(min_sats=20000)
