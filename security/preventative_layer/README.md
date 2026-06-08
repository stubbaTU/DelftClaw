# AgentDojo + VukZero SQ1 Adapter

This package lets SQ1 use AgentDojo as the external attack suite while keeping
VukZero as the only changed condition.

Conditions:

- `C0_agentdojo_baseline`: AgentDojo tools execute normally.
- `C1_agentdojo_vukzero`: the same AgentDojo tool calls are mediated by
  VukZero `ToolBroker` and `PermissionEngine`.

The adapter does not rewrite AgentDojo tasks, attacks, or scoring. It wraps the
AgentDojo `FunctionsRuntime` tool functions at the tool-execution boundary.

The SQ1 security boundary is tool-agnostic:

- tools are classified from trusted metadata into `READ_AUTHORITATIVE`,
  `READ_CONTENT`, or `EFFECT`;
- unknown or ambiguous tools default to `EFFECT`;
- a deterministic trusted-task planner issues task-scoped capabilities for
  effect tools;
- authoritative reads contribute only identifier-like fields to trusted
  provenance;
- content reads remain untrusted;
- every effect call must have both a matching capability and acceptable
  argument provenance.

AgentDojo-specific per-tool maps and email/file/calendar validators are not
part of the enforcement path.

Run the local smoke path:

```bash
python -m security.preventative_layer.agentdojo_runner \
  --suite workspace \
  --attack important_instructions \
  --model inclusionai/ling-2.6-flash \
  --conditions C0_agentdojo_baseline C1_agentdojo_vukzero \
  --logdir results/agentdojo_vukzero_workspace \
  --dry-run
```

Run the real workspace comparison after installing AgentDojo and configuring an
OpenRouter key:

```bash
export OPENROUTER_API_KEY="your_openrouter_key"
```

```bash
python -m security.preventative_layer.agentdojo_runner \
  --suite workspace \
  --attack important_instructions \
  --model inclusionai/ling-2.6-flash \
  --conditions C0_agentdojo_baseline C1_agentdojo_vukzero \
  --logdir results/agentdojo_vukzero_workspace
```

Run only the baseline:

```bash
python -m security.preventative_layer.agentdojo_runner \
  --suite workspace \
  --attack important_instructions \
  --model inclusionai/ling-2.6-flash \
  --conditions C0_agentdojo_baseline \
  --logdir results/agentdojo_vukzero_workspace
```

Run only VukZero:

```bash
python -m security.preventative_layer.agentdojo_runner \
  --suite workspace \
  --attack important_instructions \
  --model inclusionai/ling-2.6-flash \
  --conditions C1_agentdojo_vukzero \
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
