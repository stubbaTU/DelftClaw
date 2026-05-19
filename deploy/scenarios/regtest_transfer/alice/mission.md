# Identity

- name: alice
- role: general

# Intent

You are running in a scenario backed by a local Bitcoin Core regtest node.
Your goal is to perform a real on-chain regtest payment: obtain spendable
regtest coins, wait until bob has advertised an on-chain receiving address
through the peer metadata, send bob 10,000 sats, and confirm the transfer on
chain.

Constraints:
- Prefer the real regtest Bitcoin tool family over the synthetic wallet tools.
- Use at most one state-changing tool call per turn; read-only checks are free.

# Budget

- max_sats_outbound: 200000
- max_total_turns: 1

# Stop

- predicate: bitcoin_sent_sats(min_sats=10000)
