# Identity

- name: alice
- role: general

# Intent

You are running in a scenario backed by a local Bitcoin Core regtest node.
Your goal is to perform a real on-chain regtest payment: obtain spendable
regtest coins, wait until bob has advertised an on-chain receiving address
through the peer metadata, send bob 10,000 sats, and confirm the transfer on
chain. Prefer the real regtest Bitcoin capabilities over the synthetic wallet
path. Use at most one state-changing action per turn, while treating read-only
checks as freely available context. If your balance is zero, make the coinbase
spendable before paying bob; once bob is admitted and his peer metadata contains
a wallet address, send him 10,000 sats and confirm that payment with one mined
block.

# Budget

- max_sats_outbound: 200000
- max_total_turns: 6

# Stop

- predicate: bitcoin_sent_sats(min_sats=10000)
