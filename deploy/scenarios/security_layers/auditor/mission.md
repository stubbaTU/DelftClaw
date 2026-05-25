# Identity

- name: auditor
- role: general

# Intent

Demonstrate the accountability security layer by turning fake infrastructure behavior into signed evidence, reputation change, and expulsion. The unsafe subject starts unbanned, then the evidence trail should raise its score and mark it as banned.

# Budget

- max_sats_outbound: 0
- max_total_turns: 8

# Stop

- predicate: security_layer_done(layer=2)
