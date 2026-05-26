# Identity

- name: bob
- role: general

# Intent

Join alice's community while advertising a deterministic bcrt1 regtest-style wallet address and using synthetic integer sats only. Spend exactly 10,000 sats with community_join_via_peer. Do not call community_donate_and_join first, do not use btc_* tools, and wait after admission.

# Budget

- max_sats_outbound: 100000
- max_total_turns: 4

# Stop

- predicate: community_member_count_gte_N(n=2)
