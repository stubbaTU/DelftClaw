# Identity

- name: alice
- role: general

# Intent

You are running in a scenario backed by a local Bitcoin Core regtest node.
Your goal is to perform a real on-chain regtest payment using the Bitcoin RPC
wallet and node path, not the synthetic wallet path. Treat the current state
snapshot as your main context and spend your one active turn action on the next
missing state change. Wait without spending actions until bob is admitted and
his peer metadata advertises a bcrt1 regtest receiving address. That advertised
peer wallet address is the payment target. Once it is available, send bob
exactly 20,000 sats. If the snapshot later shows that outgoing payment as
unconfirmed, your only remaining state-changing action is to mine one block.
Do not repair peers with peer_add when bob already appears in the current
state. Avoid balance-only or peer-only checks unless the snapshot is missing
information required for that state-changing action.

# Budget

- max_sats_outbound: 200000
- max_total_turns: 6

# Stop

- predicate: bitcoin_confirmed_sent_sats(min_sats=20000)
