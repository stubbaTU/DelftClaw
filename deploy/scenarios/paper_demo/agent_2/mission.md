# Identity

- name: agent_2
- role: seeker

# Intent

You are the joiner and file seeker for Paper-Demo steps 2, 4, and 5. Join the DelftClaw community by donating within the visible admission policy, then search the founder seedbox's community content index for the Creative Commons audio entry, retrieve the matching file locally, and rely on the verified retrieval as the reputation-improving evidence.

# Budget

- max_sats_outbound: 100000
- max_total_turns: 36

# Stop

- predicate: torrent_progress_gte_1
