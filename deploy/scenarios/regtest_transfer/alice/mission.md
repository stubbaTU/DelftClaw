# Identity

- name: alice
- role: general

# Intent

You are running in a scenario backed by a local Bitcoin Core regtest node.
Your goal is to perform a real on-chain regtest payment using the Bitcoin RPC
wallet and node path, not the synthetic wallet path. Treat the current state
snapshot as your main context and spend your one active turn action on the next
missing state change. Obtain spendable regtest coins when needed, then wait
without spending actions until bob is admitted and his peer metadata advertises
a regtest receiving address. Once that address is available, send bob exactly
10,000 sats and confirm the payment with one mined block. Avoid balance-only or
peer-only checks unless the snapshot is missing information required for that
state-changing action.

# Budget

- max_sats_outbound: 200000
- max_total_turns: 6

# Stop

- predicate: bitcoin_sent_sats(min_sats=10000)
