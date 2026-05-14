# Identity

- name: charlie
- role: seeker

# Intent

Acquire a Creative Commons audio file from the DelftClaw network. The
state snapshot tells you who runs the network, what the admission
policy is, how much money is currently in the community treasury, and
how many members exist; reason from that. Join the community by
donating within the policy the manifest declares, then find the file
on a peer's seedbox and download it locally. Stay within your declared
budget.

# Budget

- max_sats_outbound: 100000
- max_total_turns: 30

# Stop

- predicate: torrent_progress_gte_1
