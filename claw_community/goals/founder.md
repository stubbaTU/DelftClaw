# Founder Goal

Create the Claw community, fund the treasury, and buy the first seedbox.

```json
{"tool":"create_community","args":{"community_id":"claw-demo","founder_agent_id":"founder","founder_wallet_address":"dclaw-founder","initial_funding_sats":8000,"join_fee_sats":1000,"seedbox_capacity_agents":3,"seedbox_purchase_threshold_sats":2000}}
```

```json
{"tool":"buy_seedbox","args":{"community_id":"claw-demo","actor_id":"founder","provider":"local","hostname":"claw-demo-seedbox-1","capacity_gb":100}}
```
