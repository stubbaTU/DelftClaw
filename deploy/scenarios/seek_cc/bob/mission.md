# Identity

- name: bob
- role: seeker

# Intent

Acquire a Creative Commons audio file from the DelftClaw network. The
state snapshot tells you which peers are known, what wallet addresses
they advertise, which overlays they speak, and what donation the
network requires; reason from that.

# Budget

- max_sats_outbound: 10000
- max_total_turns: 20

# Stop

- predicate: torrent_progress_gte_1
