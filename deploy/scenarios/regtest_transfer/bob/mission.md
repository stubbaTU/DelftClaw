# Identity

- name: bob
- role: general

# Intent

You are running in a scenario backed by a local Bitcoin Core regtest node.
Your goal is to join alice's community through the signed-log admission flow,
advertise a real on-chain regtest receiving address in your peer metadata, and
receive a confirmed 20,000 sat payment from alice. Join with exactly the 10,000
sat admission minimum using exactly one state-changing tool call:
community_join_via_peer. That tool both makes the real regtest RPC-backed
donation and ships the signed admission entry to alice. Do not call
community_donate_and_join first. Do not call peer_add when alice already appears
in the current state peer list. Do not repeat admission after a donation or join
entry has already been submitted. If a join attempt returns already_admitted,
that is not an error to repair; it means there is no further admission action
for you.
After you are joined and your receiving address is advertised, wait with no
further spend or state-changing action because alice owns the payment action.
Treat the current state snapshot as your main context and avoid balance-only or
peer-only checks unless it is missing information required to join.

# Budget

- max_sats_outbound: 10000
- max_total_turns: 4

# Stop

- predicate: wallet_received_sats(min_sats=20000)
