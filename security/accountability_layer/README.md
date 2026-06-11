# SQ2 Tamper-Evident Accountability

This package implements the SQ2 live OpenClaw-agent measurement harness.

For the full implementation, evaluation methodology, results, and
interpretation, see:

```text
security/accountability_layer/ACCOUNTABILITY_SYSTEM_TECHNICAL_OVERVIEW.md
```

SQ2 asks whether tamper-evident behavioral recording plus trustworthy
estimation reduces reputation lag and fallout radius during Reputation Trap
Attacks. It is not a private-key exfiltration or prompt-injection ASR test.

## Generate Scenarios

```bash
python -m security.accountability_layer.evaluation.generate_live_scenarios \
  --out security/datasets/sq2_live_reputation_trap_scenarios.jsonl
```

The frozen corpus contains 60 scenarios:

```text
4 families x 3 intensities x 5 seeds = 60 scenarios
```

Each scenario has 8 honest agents, one primary attacker (`M0`), and two sybils
(`S1`, `S2`). Ground-truth labels are used only by the evaluator, not by the
trustworthy estimator.

For a larger deterministic corpus, increase the number of seeds per
family/intensity cell:

```bash
python -m security.accountability_layer.evaluation.generate_live_scenarios \
  --seeds-per-cell 25 \
  --out security/datasets/sq2_live_reputation_trap_scenarios_large.jsonl
```

This produces:

```text
4 families x 3 intensities x 25 seeds = 300 scenarios
```

## Run A Smoke Test

```bash
python -m security.accountability_layer.evaluation.live_orchestrator \
  --mode deterministic \
  --conditions C0_naive_reputation C1_vukzero_accountability \
  --limit 2 \
  --out results/sq2_smoke
```

## Run The Live OpenClaw-Agent Experiment

```bash
python -m security.accountability_layer.evaluation.live_orchestrator \
  --mode live-llm \
  --conditions C0_naive_reputation C1_vukzero_accountability \
  --out results/sq2_accountability_$(date -u +%Y%m%dT%H%M%SZ) \
  --base-url "$OPENCLAW_BASE_URL" \
  --model "$OPENCLAW_MODEL" \
  --api-key "$OPENROUTER_API_KEY" \
  --max-iterations 5 \
  --estimator-interval 1 \
  --expulsion-threshold 5
```

`live-llm` drives the SQ2 OpenClaw-style tool loop with a real
OpenAI-compatible model. Add `--start-openclaw-runtime` only when the VPS has
the full IPv8/OpenClaw runtime dependencies installed and you specifically want
to start disposable network runtimes for each actor.

## Conditions

`C0_naive_reputation` uses a naive mutable reputation state. It accepts
self-reported microtask claims, donation-like events, and endorsements with no
append-only evidence chain or history-based estimator.

`C1_vukzero_accountability` writes behavior to the existing
`SignedAppendOnlyLog`, verifies the chain, estimates trustworthiness from the
signed log, and writes policy violations plus expulsion decisions back into the
same log.

`B1_rules_mutable` runs the full history-based estimator over a plain mutable
JSONL log. It isolates the integrity contribution of the signed log.

`B2_signed_nopattern` retains the signed log but disables cyclic wash-trade,
three-node, and linked-endorsement-cluster reconstruction. It isolates the
detection contribution of cross-agent pattern analysis.

## Redesigned Evaluation

The reviewer-oriented SQ2 redesign adds adaptive attackers, ambiguous-honest
agents, ablations, a measured tamper attack, threshold sweeps, survival
analysis, effect sizes, and confidence intervals. The complete VPS procedure
is documented in the "VPS Workflow" section of
`ACCOUNTABILITY_SYSTEM_TECHNICAL_OVERVIEW.md`.

The full live runner defaults to the GPT-4o-mini alias used by the current
AgentDojo evaluation:

```bash
nohup security/accountability_layer/run_sq2_accountability_evaluation.sh > results/sq2_factorial_master.log 2>&1 &
```

Post-hoc analysis does not invoke the model:

```bash
python -m security.accountability_layer.evaluation.rescore_logs --run-dir <run> --out <analysis>
python -m security.accountability_layer.evaluation.sweep_thresholds --run-dir <run> --out <analysis>
python -m security.accountability_layer.evaluation.sq2_statistics --trials <run>/sq2_trials.csv --out <analysis>
```

The threshold sweep emits the complete sweep, an ROC-style table, a
detection/false-positive Pareto frontier, and a selected operating point using
the stated false-positive constraint.

## Metrics

The primary metric is reputation lag:

```text
reputation_lag_events = expulsion_event_index - first_malicious_event_index
reputation_lag_rounds = expulsion_round - first_malicious_round
```

If the attacker is not expelled by the end of the scenario, the run is censored
and lag is measured to the last scenario event.

Fallout radius is captured with:

```text
fallout_broadcasts
fraudulent_microtasks_accepted
wash_trades_accepted
collusive_endorsements_accepted
fraudulent_reputation_gain
false_positive_count
false_positive_rate
```

## Outputs

The runner exports:

```text
sq2_run_metadata.json
sq2_summary.json
sq2_scenarios.jsonl
sq2_trials.csv
sq2_trials.jsonl
sq2_event_log.jsonl
sq2_reputation_timeseries.csv
sq2_expulsions.csv
sq2_lag_by_condition.csv
sq2_lag_by_family.csv
sq2_fallout_by_condition.csv
sq2_fallout_by_family.csv
sq2_detection_reasons.csv
sq2_false_positives.csv
sq2_log_integrity.csv
```

Per-scenario C1 signed logs are written under:

```text
trials/C1_vukzero_accountability/<scenario_id>/accountability.log
```
