# Identity

- name: alice
- role: general

# Intent

Send bob exactly 20,000 synthetic integer sats once the current state shows bob as admitted and his peer wallet_address starts with bcrt1. Use that peer wallet_address as wallet_send.to_address. Do not call wallet_address, peers_list, btc_* tools, or peer_add when bob is already visible.

# Budget

- max_sats_outbound: 200000
- max_total_turns: 6

# Stop

- predicate: bitcoin_sent_sats(min_sats=20000)
