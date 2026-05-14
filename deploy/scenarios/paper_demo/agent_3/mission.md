# Identity

- name: agent_3
- role: general

# Intent

Join the DelftClaw paper demo community by donating within the visible admission policy, then stay available as an ordinary member so the signed community log shows three admitted agents using the first seedbox.

# Budget

- max_sats_outbound: 100000
- max_total_turns: 36

# Stop

- predicate: community_member_count_gte_N(n=3)
