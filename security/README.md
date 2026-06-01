# DelftClaw Security Research Code

This directory contains the active security code for the three thesis
subquestions plus a small amount of deploy compatibility code that is still
referenced by existing demos.

## Active Thesis Packages

- `security/agentdojo_vukzero/`: SQ1 AgentDojo evaluation for tool-level
  prevention with VukZero capability checks.
- `security/subq2_accountability/`: SQ2 accountability evaluation with signed
  logs, reputation lag, fallout metrics, and live/deterministic scenarios.
- `security/subq3_containment/`: SQ3 system containment evaluation with mock
  protected resources, hardened proxies, gVisor/iptables enforcement checks,
  deterministic attack probes, result exports, and paper tables.
- `security/permissions/`: shared Brain/Hands permission primitives used by
  SQ1 and the OpenClaw tool broker.
- `security/contracts.py` and `security/results.py`: shared dataclasses and
  result helpers used across the security experiments.

## Retained Compatibility Code

- `security/subq1_preventative/` and `security/integration/` are retained
  because deploy/community-demo entrypoints and tests still import them. They
  are not the current SQ1 paper evaluation path; the current SQ1 path is
  `security/agentdojo_vukzero/`.

The old SQ3 integrity/sandbox package was removed. Its only active helper, the
real gVisor/iptables preflight probe, now lives in
`security/subq3_containment/enforcement.py`.

## Common Commands

SQ1 AgentDojo:

```bash
python -m security.agentdojo_vukzero.agentdojo_runner \
  --suite workspace \
  --attack tool_knowledge \
  --conditions C0_agentdojo_baseline C1_agentdojo_vukzero
```

SQ2 accountability:

```bash
python -m security.subq2_accountability.live_orchestrator \
  --mode deterministic \
  --scenarios security/datasets/sq2_live_reputation_trap_scenarios.jsonl \
  --conditions C0_naive_reputation C1_vukzero_accountability \
  --out results/sq2_accountability_deterministic_60
```

SQ3 containment:

```bash
python -m security.subq3_containment.official_runner \
  --out results/sq3_official_containment \
  --timeout 10 \
  --image python:3.12-slim
```
