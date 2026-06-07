# Lineage Experiment Results

This directory contains the configuration and generated artifacts for the
lineage experiment pipeline. One orchestration command runs verifier-level,
admission-level, real-agent, storage, performance, table, figure, and summary
stages into one timestamped run directory.

## Claim Boundary

The verifier and real-agent admission experiments currently use mock anchor
records. The real-agent stage runs actual `agent.runtime.OpenClawAgent`
instances and the signed IPv8 lineage challenge/proof path, but it does not
evaluate Bitcoin regtest OP_RETURN anchoring, Bitcoin RPC, mining, mempool,
transaction broadcast, or block-header latency.

## Directory Layout

```text
results/
  config/
    default.json
    smoke.json
  runs/
    <run_id>/
      config.json
      environment.json
      raw/
      tables/
      figures/
      summary.json
  summary.json
```

`results/summary.json` points to the latest completed run. All raw CSVs,
derived tables, and figures for a run remain together under its run directory.

## Reproduction

Smoke run:

```powershell
cd C:\School\RP
.\.venv\Scripts\python.exe -m experiments.run_all --config results\config\smoke.json --out results\runs --smoke
```

Full paper run:

```powershell
cd C:\School\RP
.\.venv\Scripts\python.exe -m experiments.run_all --config results\config\default.json --out results\runs
```

Lineage-focused unit tests:

```powershell
cd C:\School\RP
.\.venv\Scripts\python.exe -m pytest identity\tests\test_lineage_mvp.py tests\test_lineage_tools.py tests\test_runtime_lineage.py tests\test_lineage_handshake.py tests\test_network_manifest.py tests\test_scenario_manifest.py
```

Use `--skip-admission` to record every admission combination as explicitly
unsupported. Use `--continue-on-optional-failure` to preserve and report an
admission-stage failure while completing the required local experiment stages.
Other stage failures always stop the pipeline with a non-zero exit code.

## Raw CSVs

- `functional_correctness.csv`: valid-proof acceptance, certificate counts,
  Merkle proof sizes, anchor metadata, and verifier status by lineage depth.
- `adversarial_rejection.csv`: rejection outcomes and verifier statuses for
  each configured mutation or explicitly unsupported attack case.
- `storage_scaling.csv`: serialized proof and persisted lineage-store sizes by
  lineage depth.
- `performance_latency.csv`: warmup and measured local latency for certificate
  issuance, Merkle construction, mock anchor creation, cold verification, and
  cached verification.
- `admission_modes.csv`: IPv8 admission outcomes for disabled, optional, and
  required modes with valid, invalid, missing, and replayed proofs.
- `real_agent_adversarial.csv`: actual `OpenClawAgent` join outcomes and
  recorded lineage statuses for the configured adversarial matrix.

The hosted-model experiment is deliberately excluded from `run_all`:

- `openclaw_llm_adversarial.csv`: real OpenClaw/OpenRouter tool selection and
  real IPv8 lineage admission outcomes, reported as separate dimensions.
- `openclaw_llm_adversarial_summary.csv`: LLM task success over all attempts
  and protocol correctness over attempted joins only.

Run its first milestone explicitly on the VPS:

```bash
python -m experiments.run_openclaw_llm_adversarial \
  --config results/config/smoke.json --out results/runs --milestone
```

See `docs/openclaw_llm_adversarial_experiment.md` for preflight, smoke, full
matrix, evidence, and data-retention details.

Every CSV records the run id, seed, timestamp, Git commit, Python version, and
platform. Schemas are exact and validated before summary generation.

## Tables And Figures

The `tables/` directory contains one summary CSV per raw experiment plus
`summary.csv`, which combines publication-oriented metrics and descriptive
statistics. `real_agent_adversarial_summary.csv` groups join, rejection, false
accept, and duration results by mode and attack. These files are regenerated
from raw CSVs.

The `figures/` directory contains:

- `verification_latency_by_depth.png`
- `cached_vs_cold_verification.png`
- `merkle_batch_latency.png`
- `storage_by_depth.png`

The plots are generated from `performance_latency.csv` and
`storage_scaling.csv`; they do not contain manually entered measurements.

## Using Results In The Paper

Cite the selected run directory's `summary.json` as the reproducibility record.
Cite the corresponding raw CSVs and generated figures or tables for individual
claims. Do not cite manually edited tables. Preserve `config.json` and
`environment.json` with any archived result set.

## Limitations

- Anchoring is mocked; no Bitcoin Core or OP_RETURN integration is evaluated.
- Real-agent results cover controlled local OpenClaw/IPv8 admission, not a
  production or hostile-network deployment.
- Replay detection records a stale payload but does not retroactively evict an
  already admitted peer.
- OS randomness may affect cryptographic keys even when experiment labels,
  ordering, and mutations use a fixed seed.
- IPv8 admission experiments may be timing-sensitive.
- Capability checks validate explicit labels, not semantic permissions.
- Results depend on the local Python environment and installed dependencies
  captured in `environment.json`.
