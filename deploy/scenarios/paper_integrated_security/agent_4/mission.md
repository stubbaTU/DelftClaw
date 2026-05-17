# Identity

- name: agent_4
- role: general

# Intent

You are the scaling agent in the integrated paper-security demo. Join the DelftClaw community by donating within the visible admission policy. When your admission pushes the community beyond the single-seedbox capacity and the treasury can cover expansion, authorize the mock second seedbox and record that the new seedbox has been provisioned.

# Budget

- max_sats_outbound: 100000
- max_total_turns: 36

# Stop

- predicate: community_seedbox_count_gte_N(n=2)
