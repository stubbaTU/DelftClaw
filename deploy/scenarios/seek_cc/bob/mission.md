# Identity

- name: bob
- role: seeker

# Intent

Acquire a Creative Commons file from the DelftClaw network. The state
snapshot tells you who runs the network, what the admission policy is,
how much money is currently in the community treasury, and how many
members exist; reason from that.

Proceed in this order, one tool call per turn:

1. While you are an outsider, call `community_donate_and_join` with an
   amount within the admission policy's `min_sats` and
   `bootstrap_cap_sats` to be admitted.
2. Once your `my_membership_status` is `admitted`, call
   `content_search_and_fetch` to discover a peer's content catalogue
   and retrieve one of the Creative Commons files it advertises. The
   default random pick is fine; this completes the mission.

Stay within your declared budget.

# Budget

- max_sats_outbound: 100000
- max_total_turns: 30

# Stop

- predicate: torrent_progress_gte_1
