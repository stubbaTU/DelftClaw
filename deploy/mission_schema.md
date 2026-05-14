# DelftClaw Mission Descriptor Schema (v1)

A **mission descriptor** is the one markdown file an autonomous agent
reads at boot to know what it is, what it wants, what it may spend,
and when to stop. Together with the network manifest (admission
policy + genesis peers) and the live state snapshot (peers, overlays,
wallet, torrents), the mission is the *only* operator-supplied input
the watchdog feeds the LLM. There is no second "goal" file, no
hidden persona, no embedded recipe.

The schema is strict on purpose. Past iterations of this project had a
seven-step recipe inside `goal.md` that pre-encoded the solution — the
agent was not deciding, it was following. To stop that drift, the
parser refuses any mission that mentions a registered tool name or
contains a step-by-step list under `# Intent`.

## Required sections (in this order)

```
# Identity
# Intent
# Budget
# Stop
```

Section bodies may contain free text. The parser consumes only the
structured blocks below; a section that omits its required structured
block is a schema error.

## `# Identity`

Required key/value list. One per line, formatted `- key: value`.

| Key | Type | Notes |
|---|---|---|
| `name` | snake_case string | Should match the agent's name in `scenario.yaml`. |
| `role` | one of `seedbox`, `seeker`, `general` | Coarse intent class; informative — the parser only checks the value is in the closed set. |

## `# Intent`

Free-form prose, one paragraph. Tells the agent *what* it wants in the
operator's words. **Forbidden** here:

- Backtick-quoted strings that match a registered tool name
  (`peers_list`, `wallet_send`, `network_join`, `overlay_invoke`, etc.).
  These belong in the tool layer, not the intent.
- Numbered or bulleted lists with ≥ 3 entries — that's a recipe, not
  an intent. Two bullets are tolerated for genuine constraint lists
  ("must use Creative Commons; must not exceed budget").

The parser enforces both rules at scenario-boot time. Operators who
need to communicate procedural detail belong in a separate operator
runbook, not in the mission.

## `# Budget`

Required key/value list.

| Key | Type | Notes |
|---|---|---|
| `max_sats_outbound` | uint64 | Total satoshis this agent may spend across all wallet operations. The runtime does not enforce this — it is a *soft* contract the LLM is shown each turn. |
| `max_total_turns` | uint16 | Operator-visible cap on watchdog turns. The watchdog's separate `max_total_turns` in `scenario.yaml` is authoritative; this value is informational for the LLM. |

## `# Stop`

Required key/value list.

| Key | Type | Notes |
|---|---|---|
| `predicate` | string | Must resolve via `deploy.stop_predicates.resolve(...)`. The watchdog evaluates this predicate each tick; the LLM never decides termination. |

## Parse-time guarantees

`deploy.mission.parse_mission(text)` raises `MissionParseError` if:

1. Any required section is missing or out of order.
2. `# Identity` lacks `name` or `role`, or `role` is outside the closed set.
3. `# Intent` references a registered tool name, OR contains a list
   with ≥ 3 bullets/numbered items.
4. `# Budget` lacks `max_sats_outbound` or `max_total_turns`, or
   either is not a non-negative integer.
5. `# Stop` lacks `predicate`, or `predicate` does not resolve via
   `deploy.stop_predicates.resolve(...)`.

The watchdog calls `parse_mission(...)` at scenario boot, before
spawning any LLM turn — so a malformed mission fails fast, not mid-run.
