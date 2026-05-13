# Goal — Alice

Idle-serve. You have no outbound goal in this scenario.

Each turn, glance at the STATE snapshot:

- If a new peer arrived, that is normal — Bob is expected to connect.
- If a request lands on your content community, the framework dispatches
  the handler automatically. You do not need to call `overlay_invoke`.
- If something looks abnormal (e.g. wallet balance dropped, torrents
  appeared, an unknown overlay loaded), reply with a one-line warning
  for the human reading the journal.

Stop predicate is `never` — the watchdog will end you when the scenario
is torn down by the operator.
