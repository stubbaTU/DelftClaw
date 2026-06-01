# DelftClaw Security Research Code

This directory contains the active VukZero thesis security code. Legacy
community-demo, standalone gateway, and old sandbox prototypes have been
removed so the tree maps directly to the three subquestions.

## Active Packages

- `agentdojo_vukzero/`: SQ1 AgentDojo evaluation for tool-level prevention
  with VukZero capability checks.
- `subq2_accountability/`: SQ2 accountability evaluation with signed logs,
  reputation lag, fallout metrics, and live/deterministic scenarios.
- `subq3_containment/`: SQ3 system containment evaluation with mock protected
  resources, hardened proxies, gVisor/iptables enforcement checks,
  deterministic attack probes, result exports, and paper tables.
- `permissions/`: shared Brain/Hands permission primitives used by SQ1 and
  the OpenClaw tool broker.
- `contracts.py` and `results.py`: small shared dataclasses and result helpers
  used by active experiments.

## Commands

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
