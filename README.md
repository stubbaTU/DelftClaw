# VukZero — Zero-Trust for Autonomous LLM Agents

## About this repository

This repository, **DelftClaw**, is a research prototype of a decentralized
seedbox collective built on autonomous OpenClaw agents. Its agents form a
peer-to-peer community: they admit new members through donation evidence,
exchange file indexes and content, perform verifiable seedbox microtasks, and
provision additional seedboxes as the community grows. DelftClaw is the shared
platform that this work runs on and is evaluated against.

This README covers **VukZero**, the zero-trust security subproject built for that
setting. (For the broader DelftClaw platform components, see their own
documentation; everything below is the VukZero security work.)

## VukZero

VukZero is a zero-trust security architecture for autonomous, tool-using LLM
agents operating in an untrusted, decentralized multi-agent setting (the
DelftClaw seedbox collective). It assumes no agent, input, or host is trusted
by default and enforces trust through verification at every stage of a
compromise, rather than only at the perimeter.

It is organized as three layers, each defending a different stage of an agent
compromise. They are independent and each is evaluated against the threat it
targets:

| Layer | What it does | Lives in |
|---|---|---|
| **L1 — Preventative** | A default-deny permission monitor between the LLM and its tools: capabilities authorize *actions*, value-provenance checks stop injected values from reaching effects. Blocks prompt-injection-driven tool calls before they execute. | `security/preventative_layer/` |
| **L2 — Accountability** | A tamper-evident, Ed25519-signed, hash-chained behavioral log plus a history-based trustworthy estimator. Records behavior, detects reputation-manipulation patterns across agents, and expels offenders — even after a compromise. | `security/accountability_layer/` |
| **L3 — Containment** | A least-exposure data architecture: protected assets are never mounted in the agent container, sensitive operations are reachable only through narrow host-side proxies, and egress is firewalled — with gVisor and container hardening as defense in depth. | `security/containment_layer/` |

Each layer's directory has its own README with the full design, evaluation, and
results. A combined single-process demo that runs all three layers together is in
`security/integration/`.

## Repository Layout (security subproject)

```text
security/
  preventative_layer/    # L1 permission system (infrastructure/ + evaluation/ + results/)
  accountability_layer/  # L2 signed log + trustworthy estimator (+ evaluation/ + results/)
  containment_layer/     # L3 least-exposure + proxies + gVisor (+ evaluation/ + results/)
  integration/           # single-process full-stack end-to-end demo of L1+L2+L3
  datasets/              # frozen reputation-trap scenario corpora (L2)
tests/                   # pytest suite for all three layers
requirements.txt         # Python dependencies
requirements.lock.txt    # pinned versions used to produce the reported results
```

Each layer splits into `infrastructure/` (the VukZero mechanism being tested) and
`evaluation/` (the harness that measures it); measured artifacts live in each
layer's `results/`.

The architecture is implemented and evaluated on top of a research prototype of a
decentralized OpenClaw seedbox collective; this README covers only the VukZero
security layers.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the layer test suites (deterministic, no network/Docker required):

```bash
python -m pytest tests/test_permissions_*.py tests/test_agentdojo_vukzero_*.py \
  tests/test_subq2_*.py tests/test_subq3_*.py tests/test_signed_*.py -q
```

## Running the Evaluations

Each evaluation has step-by-step instructions in its layer README. In brief:

- **L1 (preventative)** — mediates the AgentDojo `tool_knowledge` attack across
  four suites:
  ```bash
  bash security/preventative_layer/run_c1_vukzero_all4_toolknowledge.sh
  ```
- **L2 (accountability)** — the factorial reputation-trap evaluation plus the
  tamper experiment:
  ```bash
  bash security/accountability_layer/run_sq2_accountability_evaluation.sh
  bash security/accountability_layer/run_sq2_tamper_experiment.sh
  ```
- **L3 (containment)** — the 3×2 factorial on a prepared host (Docker, gVisor,
  AppArmor, nftables):
  ```bash
  bash security/containment_layer/prepare_vps.sh
  bash security/containment_layer/run_factorial_vps.sh
  ```
- **End-to-end** — one process exercising all three layers in the strongest
  containment configuration:
  ```bash
  python -m security.integration.e2e_fullstack
  ```

The L1/L2 evaluations use a real LLM through an OpenAI-compatible endpoint; L3 is
deterministic. See each layer README for environment and configuration details.

## Results at a Glance

- **L1:** lower attack success rate than both an undefended baseline and a
  state-of-the-art privilege-control defense — macro-average ASR 3.81% (vs 29.47%
  undefended, 8.66% baseline), with zero measured injection success in three of
  four suites, at a measured utility cost.
- **L2:** the full system expelled the primary attacker in every naive
  reputation-trap scenario where the naive baseline expelled none, cutting mean
  fallout by ~56%; cross-agent pattern reconstruction drives detection and the
  signed log detects tampering that a mutable log silently loses.
- **L3:** the least-exposure architecture, not runtime hardening, is the dominant
  containment factor — mean containment rose from 30.56% to 94.44% when enabled,
  and the full gVisor-backed stack contained every probe with no breached
  category and no blocked legitimate action.

Full numbers, conditions, and limitations are in each layer's README; the
underlying artifacts are committed under each layer's `results/`.

## Reproducibility

- Frozen scenario corpora are in `security/datasets/`; the deterministic probe
  battery and its hash are recorded in the L3 results.
- `requirements.lock.txt` pins the exact dependency versions used to produce the
  reported results.
- Each evaluation records pinned run metadata (model, endpoint, seeds, container
  image digest, runtime versions, profile hashes) alongside its outputs.

## Configuration

The model-using evaluations read an OpenAI-compatible endpoint and API key from
the environment; the containment evaluation runs on a disposable host prepared by
`security/containment_layer/prepare_vps.sh`. Do not commit API keys, wallet
seeds, private keys, or machine-specific overrides.
