# VukZERO Preventative Layer — Agent Permission System

## Summary

The preventative layer is a **default-deny reference monitor** placed between an
LLM agent and its tools. The model may *propose* tool calls, but it can never
execute a tool's raw implementation directly: every proposed call is classified,
checked, and then either run or refused with a safe denial.

The monitor exists to stop the central failure mode of tool-using agents:
**indirect prompt injection**, where attacker-controlled content read at runtime
(an email body, a document, a peer message) tricks the model into issuing an
unauthorized privileged action. The layer does not try to make the model ignore
malicious text; it ensures that a model-influenced request cannot *become* an
unauthorized effect.

Every effect decision reduces to one rule:

```
allow(call) = policy(call) AND capability(call) AND provenance(call) AND egress(call)
```

Two checks carry the security argument and two are supporting guards:

- **capability** — was this *action* authorized for this task? (stops action
  substitution, e.g. a "send email" task being used to call `delete_email`)
- **provenance** — do this call's *arguments* trace back to trusted origins?
  (stops injected values, e.g. an attacker address, from reaching an authorized
  tool)
- **policy** — a matching allow rule exists under default-deny.
- **egress** — no protected secret or key-shaped material is leaving.

## Package Layout

```
preventative_layer/
  infrastructure/      the permission system itself (reusable)
  evaluation/          the harness that measures it on a benchmark
  results/             measured result artifacts
  run_c1_vukzero_all4_toolknowledge.sh   end-to-end evaluation runner
```

## Infrastructure

`infrastructure/` is the permission system, independent of any benchmark.

**Core decision flow**

- `permissions/models.py` — the immutable vocabulary: `Subject`, `Resource`,
  `Capability`, `PermissionRequest`, `PermissionDecision`, `PolicyRule`, `Policy`.
- `permissions/effects.py` — classifies each tool into one of three effect
  classes from trusted catalog metadata, failing ambiguous tools closed:
  - `READ_AUTHORITATIVE` — a vetted structured source whose typed identifier
    fields may establish trusted origin;
  - `READ_CONTENT` — a read whose returned strings stay untrusted;
  - `EFFECT` — mutates state / sends data / reaches a sink; needs a capability.
- `permissions/permission_engine.py` — the reference monitor. Resolves the
  resource, applies default-deny policy, requires a capability for effects, runs
  the argument validators, and emits an allow/deny decision with a structured
  reason.
- `permissions/tool_broker.py` — the runtime entry point. Wraps each tool call in
  a `PermissionRequest`, asks the engine, and **only runs the real tool if
  allowed**; a denied call returns a structured refusal and never touches the
  implementation. Bounded capabilities are consumed immediately before execution.

**The two security mechanisms**

- `permissions/provenance.py` — the per-task provenance store. Seeds trusted
  values from the task text (addresses, URLs, quoted strings, amounts), records
  every `READ_CONTENT` result as untrusted, and promotes **only** typed
  identifier fields from a `READ_AUTHORITATIVE` read — and only when that read's
  own lookup inputs were already trusted. `validate_effect_provenance` then
  requires every effect argument to be trusted, distinguishing a definite
  violation from a conservative "could not establish provenance" refusal.
- `permissions/capability_store.py` + `trusted_planner.py` + `capability_builder.py`
  — capabilities are issued **before** the agent runs by a deterministic planner
  that reads only the trusted task and tool catalog, never runtime content. A
  capability binds one subject, one effect tool, and one task, with optional
  expiry, bounded uses, and task-derived literals.

**Supporting guards and plumbing**

- `permissions/policy_loader.py` / `policy_schema.py` / `default_policy.yaml` —
  load and validate the default-deny policy.
- `permissions/egress_guard.py` — blocks outgoing canaries / private-key-shaped
  material.
- `permissions/validators.py` — pluggable schema/safety checks (append-only log
  schema, nonce-only signing, payload limits, path-traversal, …).
- `permissions/resource_registry.py` — tool→resource resolution and protected
  path classification.
- `permissions/proxies.py` — narrow safe interfaces (sign a nonce without
  exposing the key, append without rewrite, …).
- `permissions/decision_log.py` — structured audit trail of every decision and
  capability grant, with `reason_code` and a `security_enforcement` vs
  `utility_ceiling` denial class.
- `permissions/openclaw_integration.py` — wires the engine and proxies together
  for live agent use.

## Evaluation

`evaluation/` inserts the permission system at the tool-execution boundary of the
**AgentDojo** benchmark so that task definitions, attacks, tools, and scoring are
identical across conditions and every difference is attributable to the defense.

- `vukzero_tool_wrapper.py` — wraps each AgentDojo tool: routes the call through
  the engine, and after an allowed read records the returned values' provenance.
- `vukzero_agentdojo_policy.py` — the generic three-rule provenance policy
  (one rule per effect class, no per-tool rules).
- `agentdojo_runner.py` — the runner; entry point
  `python -m security.preventative_layer.evaluation.agentdojo_runner`.
- `export_results.py` — writes the summary, per-trial records, decision log, and
  metrics.
- `audit_agentdojo_tasks.py` — benchmark task-audit utility.

The evaluation uses three conditions over the `workspace`, `slack`, `travel`, and
`banking` suites under the `tool_knowledge` attack with `gpt-4o-mini`:

- **C0** — the same fork, undefended (raw tools);
- **C1** — VukZERO mediates every tool call;
- **C2** — Progent, a recent privilege-control defense, as a like-for-like
  baseline.

The primary metric is **attack success rate (ASR)** — the fraction of injected
trials where the injection task succeeded (lower is better). Utility under attack
(legitimate task still completed) is reported as the trade-off.

## Results

Across 589 valid injected trials, VukZERO gave the lowest attack success rate of
the three conditions and reached zero measured injection success in three of the
four suites.

| Suite | C1 utility | C1 ASR | C0 ASR (undefended) | C2 ASR (Progent) |
|---|---:|---:|---:|---:|
| Workspace | 37.08% | **0.00%** | 9.17% | 3.33% |
| Slack | 4.76% | 15.24% | 47.62% | 14.29% |
| Travel | 33.00% | **0.00%** | 34.00% | 17.00% |
| Banking | 32.64% | **0.00%** | 27.08% | 0.00% |
| **Macro avg** | **26.87%** | **3.81%** | **29.47%** | **8.66%** |

- VukZERO reduced ASR in every suite relative to undefended, and beat Progent on
  macro-average ASR (3.81% vs 8.66%).
- The cost is utility under attack: macro utility 26.87% vs ~48% (undefended) and
  ~47% (Progent). This is the deliberate trade-off of strict value-provenance —
  it refuses legitimate effects whose argument values were discovered through
  multi-step runtime workflows it cannot trace to the task.
- Denials split into 635 `security_enforcement` (a definite policy/capability/
  provenance violation) and 342 `utility_ceiling` (conservative "could not prove
  it safe") refusals. Banking is almost entirely security enforcement; Workspace
  and Slack carry most of the utility-ceiling cost.
- Travel and Banking show the layer can hold strong security without collapsing
  utility when the task's effects map cleanly onto scoped capabilities; Slack
  (collaboration-heavy, runtime-discovered values) is the hardest case.

## Running It

End-to-end over all four suites (requires an OpenAI-compatible endpoint for the
agent-visible model):

```bash
bash security/preventative_layer/run_c1_vukzero_all4_toolknowledge.sh
```

Or a single suite directly:

```bash
python -m security.preventative_layer.evaluation.agentdojo_runner \
  --condition C1_agentdojo_vukzero \
  --suite workspace \
  --attack tool_knowledge \
  --logdir results/sq1_run
```

Results land under `results/` (curated artifacts) with per-suite
`agentdojo_vukzero_summary.json`, `..._trials.csv/.jsonl`,
`..._metrics_by_condition.csv`, `..._permission_decisions.jsonl`, and the blocked/
false-deny breakdowns.

## Tests

```bash
python -m pytest tests/test_permissions_*.py tests/test_agentdojo_vukzero_*.py -q
```

These cover provenance promotion and the denial classes, capability issuance and
expiry, the engine's allow/deny logic, the proxies, the egress guard, and the
AgentDojo wrapper.
