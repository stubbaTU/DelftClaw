# OpenClaw Identity And Lineage Experiment

This folder is the single entry point for the identity-layer work in the
OpenClaw/DelftClaw prototype. It contains the cryptographic identity code,
the proof-of-descendancy lineage implementation, and the README needed to
reproduce the local and VPS experiments that evaluate that work.

The wider OpenClaw system is a peer-to-peer mesh of agents. Agents use IPv8
for transport, Bitcoin-style donation evidence for admission, BitTorrent for
content transfer, and markdown-described protocols that can be compiled into
live IPv8 communities at runtime. This identity layer supplies the stable
agent identity material that those pieces bind to, then extends admission with
lineage proofs so a gatekeeper can decide whether a joining peer descends from
an expected trusted root.

## What This Work Covers

- Deterministic multi-key agent identity from one seed.
- Stable OpenClaw agent identifiers derived from IPv8 public keys.
- Application signing keys for signed logs and admission artifacts.
- Synthetic deterministic wallet identities for local experiments.
- Lineage certificates, Merkle batches, mock anchors, revocation checks,
  proof stores, verifier cache, and canonical JSON encoding.
- Local reproducibility pipeline for paper tables, figures, and CSVs.
- Real `OpenClawAgent` admission experiments over IPv8.
- Hosted-model OpenClaw/OpenRouter adversarial experiment on a Linux VPS.

## Repository Context

The code owned by this contribution is centered here, with experiment runners
and result outputs in shared top-level folders:

```text
identity/
  agent_identity.py          # BIP-39/BIP-32 identity bundle
  app_key.py                 # application-layer Ed25519 signing key
  derivation.py              # deterministic key derivation helpers
  ipv8_key.py                # IPv8 transport key derivation
  openclaw_identity.py       # identity type used by signed logs
  seed.py                    # mnemonic/env/keyring/keyfile seed sources
  wallet.py                  # deterministic synthetic wallet wrapper
  lineage/
    anchors.py               # anchor interfaces
    cache.py                 # verifier cache
    canonical.py             # canonical JSON encoding
    certificates.py          # child certificate issue/verify helpers
    merkle.py                # Merkle root and proof helpers
    mock_anchor.py           # mock anchoring backend used in experiments
    models.py                # lineage data models
    revocation.py            # revocation validation
    store.py                 # proof/artifact persistence
    verifier.py              # lineage proof verifier
  tests/
    test_identity_primitives.py
    test_lineage_mvp.py

experiments/
  run_all.py                         # local full pipeline, no hosted LLM
  run_functional_correctness.py      # valid proof acceptance by depth
  run_adversarial_rejection.py       # deterministic mutation rejection
  run_storage_scaling.py             # proof/store size by depth
  run_performance_latency.py         # local verifier latency
  run_admission_modes.py             # admission modes against lineage cases
  run_real_agent_adversarial.py      # real OpenClawAgent IPv8 admission
  run_openclaw_llm_adversarial.py    # hosted OpenClaw/OpenRouter experiment
  openclaw_llm_controller.py         # FastMCP tools for LLM trials

results/
  config/smoke.json
  config/default.json
  runs/<run_id>/
  summary.json
```

## Identity Model

One BIP-39 seed derives independent keys through a BIP-32 chain:

```text
m/44'/0'/0'/0/0   -> Ed25519 IPv8 transport key (LibNaCLSK)
m/44'/0'/0'/1/0   -> Ed25519 application-layer signing key
m/44'/0'/{i}'/0/0 -> synthetic wallet key for agent index i
```

The OpenClaw agent identifier is content-derived:

```text
agent_id = sha256(ipv8_raw_pubkey || network)
```

Public entry points:

- `AgentIdentity.from_seed(seed, network) -> AgentIdentity`: multi-key bundle
  consumed by `agent/runtime.py:OpenClawAgent`.
- `Seed` plus `MnemonicSeedSource`, `EnvSeedSource`, `KeyringSeedSource`, and
  `KeyfileSeedSource`: seed loading for demos, development, OS keyrings, and
  VPS-style seed files.
- `Wallet.from_seed(seed, network, agent_index)`: deterministic synthetic
  wallet wrapper for experiments and scenario bootstrapping.
- `OpenClawIdentity`: identity object used by
  `redteam/primitives/signed_log.py:SignedAppendOnlyLog`; its `reporter_id`
  is `SHA256(reporter_pubkey || network)`.

Wallet CLI example:

```bash
python -m identity.wallet --mnemonic "..." address
python -m identity.wallet --mnemonic "..." balance
python -m identity.wallet --mnemonic "..." send
```

## Lineage Protocol Summary

The lineage layer represents a proof that an agent identity descends from a
trusted root. The experiment uses mock anchors, not Bitcoin OP_RETURN, so the
claim being measured is verifier and admission behavior, not public-chain
anchoring behavior.

Core concepts:

- A root identity can issue child certificates.
- Certificate batches are summarized with Merkle roots.
- Mock anchor records bind batch roots to anchor metadata.
- A joining agent supplies a lineage proof during the IPv8 admission flow.
- The gatekeeper verifies certificate signatures, child identity binding,
  Merkle inclusion, anchor consistency, expiry, capabilities, revocation, and
  replay/stale-proof cases.
- Admission modes are `disabled`, `optional`, and `required`.

Important boundary:

```text
Anchors are mock records. The local and real-agent experiments do not evaluate
Bitcoin regtest OP_RETURN anchoring, Bitcoin RPC, mining, mempool behavior,
transaction broadcast, block-header latency, or production hostile-network
deployment.
```

## Local Setup

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Local Tests

Identity-only tests:

```bash
python -m pytest identity/tests -q
```

Lineage-focused tests used for the paper work:

```bash
python -m pytest \
  identity/tests/test_lineage_mvp.py \
  tests/test_lineage_tools.py \
  tests/test_runtime_lineage.py \
  tests/test_lineage_handshake.py \
  tests/test_network_manifest.py \
  tests/test_scenario_manifest.py
```

Windows PowerShell equivalent:

```powershell
.\.venv\Scripts\python.exe -m pytest identity\tests\test_lineage_mvp.py tests\test_lineage_tools.py tests\test_runtime_lineage.py tests\test_lineage_handshake.py tests\test_network_manifest.py tests\test_scenario_manifest.py
```

## Local Experiment Pipeline

The local pipeline is run through `experiments.run_all`. It does not invoke a
hosted model and does not require OpenRouter API traffic.

Smoke run:

```bash
python -m experiments.run_all \
  --config results/config/smoke.json \
  --out results/runs \
  --smoke
```

Full paper run:

```bash
python -m experiments.run_all \
  --config results/config/default.json \
  --out results/runs
```

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m experiments.run_all --config results\config\smoke.json --out results\runs --smoke
.\.venv\Scripts\python.exe -m experiments.run_all --config results\config\default.json --out results\runs
```

Useful flags:

- `--skip-admission`: records every admission combination as explicitly
  unsupported.
- `--continue-on-optional-failure`: preserves and reports admission-stage
  failures while still completing the required local stages.

All other stage failures stop the pipeline with a non-zero exit code.

## Local Pipeline Outputs

Each successful run creates:

```text
results/runs/<run_id>/
  config.json
  environment.json
  raw/
    functional_correctness.csv
    adversarial_rejection.csv
    storage_scaling.csv
    performance_latency.csv
    admission_modes.csv
    real_agent_adversarial.csv
  tables/
    summary.csv
    *_summary.csv
  figures/
    verification_latency_by_depth.png
    cached_vs_cold_verification.png
    merkle_batch_latency.png
    storage_by_depth.png
  summary.json
```

`results/summary.json` points to the latest completed run. Cite a selected
run directory's `summary.json`, raw CSVs, and generated tables/figures in the
paper. Do not cite manually edited tables.

## Linux VPS OpenClaw LLM Experiment

The hosted-model experiment is intentionally separate from `run_all`:

```text
experiments.run_openclaw_llm_adversarial
```

It measures OpenClaw/OpenRouter tool behavior separately from deterministic
IPv8 lineage admission correctness. It uses:

- a real `openclaw agent --local` subprocess;
- OpenRouter, default model `openrouter/owl-alpha`;
- an isolated OpenClaw `HOME` and non-reserved agent id per trial;
- a FastMCP controller exposing exactly three experiment tools;
- real `agent.runtime.OpenClawAgent` gatekeeper and joining runtimes;
- normal `SeedboxCommunity.request_join` lineage exchange.

Set the API key only in the shell that launches the runner. Do not put the key
in JSON, Git, prompts, or result metadata.

VPS preflight:

```bash
cd /opt/delftclaw
export OPENROUTER_API_KEY="..."
PYTHONPATH=/opt/delftclaw \
  /opt/delftclaw/venv/bin/python \
  -m experiments.run_openclaw_llm_adversarial \
  --config results/config/smoke.json \
  --out results/runs \
  --preflight-only
```

First milestone, validating required-mode baseline acceptance and
tampered-parent-signature rejection:

```bash
PYTHONPATH=/opt/delftclaw \
  /opt/delftclaw/venv/bin/python \
  -m experiments.run_openclaw_llm_adversarial \
  --config results/config/smoke.json \
  --out results/runs \
  --milestone
```

One-attempt smoke matrix:

```bash
PYTHONPATH=/opt/delftclaw \
  /opt/delftclaw/venv/bin/python \
  -m experiments.run_openclaw_llm_adversarial \
  --config results/config/smoke.json \
  --out results/runs \
  --smoke
```

Full matrix:

```bash
PYTHONPATH=/opt/delftclaw \
  /opt/delftclaw/venv/bin/python \
  -m experiments.run_openclaw_llm_adversarial \
  --config results/config/default.json \
  --out results/runs
```

Trials are serial to avoid provider bursts and shared-state interference.
Owl Alpha is currently configured as the default model in the experiment
config, but provider behavior and retention policies are external to this
repository. Keep missions and trial data synthetic.

## Hosted Experiment Selection Flags

The hosted runner supports selective reruns:

```bash
python -m experiments.run_openclaw_llm_adversarial \
  --config results/config/default.json \
  --out results/runs \
  --lineage-mode optional \
  --lineage-mode required \
  --attack-case valid_agent_baseline \
  --attack-case tampered_parent_signature \
  --trial-index 0 \
  --trial-index 2
```

Common flags:

| Flag | Purpose |
| --- | --- |
| `--preflight-only` | Check compatibility and model capabilities, then exit. |
| `--skip-model-qualification` | Skip live OpenRouter model-catalog check. |
| `--milestone` | Run trial `0` for required-mode baseline and tampered-parent-signature cases. |
| `--smoke` | Use smoke trial counts from the selected config. |
| `--lineage-mode MODE` | Select `disabled`, `optional`, or `required`; repeatable. |
| `--attack-case CASE` | Select configured attack cases; repeatable. |
| `--trial-index INDEX` | Select zero-based trial indices; repeatable. |
| `--log-level LEVEL` | Use `DEBUG`, `INFO`, `WARNING`, or `ERROR`. |
| `--progress-interval SECONDS` | Heartbeat interval while waiting on LLM/API calls. |

Hosted OpenClaw attack cases:

```text
valid_agent_baseline
tampered_child_certificate
tampered_parent_signature
wrong_trusted_root
broken_merkle_proof
wrong_anchor_record
expired_certificate
missing_required_capability
revoked_child_certificate
unauthorized_revocation_signer
missing_lineage_proof
cloned_agent_identity
replayed_nonce_or_stale_proof
malformed_lineage_proof_payload
```

## Hosted Experiment Outputs

Each hosted run writes:

```text
results/runs/<run_id>/
  preflight.json
  raw/openclaw_llm_adversarial.csv
  raw/openclaw_llm_adversarial/<trial_id>/
    prompt.txt
    openclaw_stdout.json
    openclaw_stderr.txt
    tool_calls.jsonl
    protocol_result.json
    metadata.json
    artifact_manifest.json
  tables/openclaw_llm_adversarial_summary.csv
```

The hosted summary reports LLM task success over all trials. Protocol
correctness is computed only for rows where the model actually attempted a
join.

## CSV Meaning

The local pipeline emits:

- `functional_correctness.csv`: valid-proof acceptance, certificate counts,
  Merkle proof sizes, anchor metadata, and verifier status by depth.
- `adversarial_rejection.csv`: rejection outcomes and verifier statuses for
  deterministic mutation cases.
- `storage_scaling.csv`: serialized proof and persisted lineage-store sizes by
  lineage depth.
- `performance_latency.csv`: local latency for certificate issue, Merkle
  construction, mock anchor creation, cold verification, and cached
  verification.
- `admission_modes.csv`: IPv8 admission outcomes for disabled, optional, and
  required lineage modes.
- `real_agent_adversarial.csv`: actual `OpenClawAgent` join outcomes and
  lineage statuses for the configured adversarial matrix.

The hosted pipeline emits:

- `openclaw_llm_adversarial.csv`: OpenClaw/OpenRouter tool selection and real
  IPv8 lineage admission outcomes.
- `openclaw_llm_adversarial_summary.csv`: LLM task success and protocol
  correctness summaries.

Every CSV records run id, seed, timestamp, Git commit, Python version, and
platform. Schemas are validated before summary generation.

## Current Limitations

- Anchoring is mocked; no Bitcoin Core or OP_RETURN integration is evaluated.
- Real-agent results cover controlled local OpenClaw/IPv8 admission, not
  hostile-network production deployment.
- Replay detection records stale payloads but does not retroactively evict an
  already admitted peer.
- OS randomness may affect cryptographic keys even when experiment labels,
  ordering, and mutations use a fixed seed.
- IPv8 admission experiments may be timing-sensitive.
- Capability checks validate explicit labels, not semantic permissions.
- Hosted-model behavior can vary by provider, model availability, and external
  service policy.

## Larger OpenClaw System Summary

This contribution plugs into the wider DelftClaw/OpenClaw prototype:

- `communication/`: `SeedboxCommunity`, bootstrap peer discovery, admission
  messages, overlay gossip, manifest exchange, and BitTorrent service.
- `protocol/`: markdown overlay schema, compiler, sandbox, registry, and
  runtime protocol loading.
- `admission/`: donation verifier for Bitcoin-style seedbox admission.
- `agent/`: `OpenClawAgent`, MCP server, tool surface, runtime wallets,
  overlays, torrents, manifests, and lineage-enabled admission path.
- `deploy/`: VPS deployment, scenario boot, watchdog loop, missions, systemd
  units, and autonomous multi-agent scenarios.
- `results/`: reproducibility artifacts for paper claims.

The canonical end-to-end OpenClaw demo is still the shared seedbox/content
scenario, but this identity work is the part that gives agents stable keys,
signed identity artifacts, and lineage-aware admission behavior.
