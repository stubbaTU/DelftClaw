# Identity

- name: alice
- role: general

# Intent

Share a deterministic bcrt1 regtest-style wallet address while using synthetic integer sats only. Once bob is admitted and advertises a bcrt1 peer wallet address, send bob exactly 20,000 sats with wallet_send. Do not use btc_* tools or peer_add when bob is already visible.

# Budget

- max_sats_outbound: 200000
- max_total_turns: 6

# Stop

- predicate: bitcoin_sent_sats(min_sats=20000)
