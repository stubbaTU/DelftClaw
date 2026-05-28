# AgentDojo + VukZero SQ1 Adapter

This package lets SQ1 use AgentDojo as the external attack suite while keeping
VukZero as the only changed condition.

Conditions:

- `C0_agentdojo_baseline`: AgentDojo tools execute normally.
- `C4_agentdojo_vukzero`: the same AgentDojo tool calls are mediated by
  VukZero `ToolBroker` and `PermissionEngine`.

The adapter does not rewrite AgentDojo tasks, attacks, or scoring. It wraps the
AgentDojo `FunctionsRuntime` tool functions at the tool-execution boundary.

Run the local smoke path:

```bash
python -m security.agentdojo_vukzero.agentdojo_runner \
  --suite workspace \
  --attack important_instructions \
  --model gpt-4o-mini-2024-07-18 \
  --conditions C0_agentdojo_baseline C4_agentdojo_vukzero \
  --logdir results/agentdojo_vukzero_workspace \
  --dry-run
```

Run the real workspace comparison after installing AgentDojo and configuring the
model credentials required by AgentDojo:

```bash
python -m security.agentdojo_vukzero.agentdojo_runner \
  --suite workspace \
  --attack important_instructions \
  --model gpt-4o-mini-2024-07-18 \
  --conditions C0_agentdojo_baseline C4_agentdojo_vukzero \
  --logdir results/agentdojo_vukzero_workspace
```

Run only the baseline:

```bash
python -m security.agentdojo_vukzero.agentdojo_runner \
  --suite workspace \
  --attack important_instructions \
  --model gpt-4o-mini-2024-07-18 \
  --conditions C0_agentdojo_baseline \
  --logdir results/agentdojo_vukzero_workspace
```

Run only VukZero:

```bash
python -m security.agentdojo_vukzero.agentdojo_runner \
  --suite workspace \
  --attack important_instructions \
  --model gpt-4o-mini-2024-07-18 \
  --conditions C4_agentdojo_vukzero \
  --logdir results/agentdojo_vukzero_workspace
```

The real AgentDojo package is not vendored in this repository. The runner uses
AgentDojo's public benchmark objects when the package is installed. Lower-level
integrations can use `wrap_functions_runtime(...)` or
`make_vukzero_pipeline_element(...)` inside an AgentDojo pipeline before tool
execution.

Outputs:

- `agentdojo_vukzero_run_metadata.json`
- `agentdojo_vukzero_summary.json`
- `agentdojo_vukzero_trials.csv`
- `agentdojo_vukzero_trials.jsonl`
- `agentdojo_vukzero_metrics_by_condition.csv`
- `agentdojo_vukzero_permission_decisions.jsonl`
- `agentdojo_vukzero_blocked_calls.csv`
- `agentdojo_vukzero_false_denies.csv`
- `run.log`
