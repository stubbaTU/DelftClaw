# VukZERO Accountability Layer — Tamper-Evident Behavioral Recording

## Summary

The accountability layer is what VukZERO relies on *after* a compromise begins.
It assumes prevention has already failed and a malicious agent is acting, and
asks a different question: can the network **record** that behavior in a way that
can't be quietly rewritten, **detect** it from history, and **expel** the
offender before too much damage accumulates?

It targets **reputation-trap attacks** in a decentralized agent collective — an
agent first builds trust, then exploits it: fake task completions, wash-trading
and self-donation, collusive endorsements between sybil identities, and delayed
rug-pulls. The damage that accrues between the first malicious event and
expulsion is the **fallout radius**, and the delay itself is the **reputation
lag** — the layer's primary metric.

Two design choices make it work:

- **A signed, hash-chained append-only log.** Every accepted event is bound to
  its predecessor and signed, so deleting, reordering, or editing past evidence
  breaks verification. Reputation decisions rest on verifiable evidence, not on
  an agent's self-report.
- **Reputation and suspicion are separate scores.** An agent can keep gaining
  reputation from accepted events while independently accumulating suspicion from
  historical patterns. Expulsion is driven by *suspicion* crossing a threshold —
  so a previously high-reputation attacker cannot use positive standing to bury
  evidence of misbehavior.

## Package Layout

```
accountability_layer/
  infrastructure/      the recording + detection system (reusable)
  evaluation/          the harness, scenario generation, and analysis
  results/             measured result artifacts
  run_sq2_accountability_evaluation.sh   full factorial + analysis runner
  run_sq2_tamper_experiment.sh           measured tamper experiment
```

Frozen scenario corpora live in `security/datasets/`.

## Infrastructure

`infrastructure/` is the system under test.

**Log substrates**

- `signed_accountability_log.py` — the signed, hash-chained append-only log used
  by the full system. `verify_integrity()` re-walks the chain, every entry hash,
  and every signature; any tampering fails verification.
- `mutable_log.py` — a plain mutable log with the *same* append/read interface
  but no cryptography, and an `erase_last_event()` method. It exists to show what
  a non-tamper-evident substrate loses. It also provides an in-memory replay
  adapter for offline re-scoring.

**Detection**

- `trustworthy_estimator.py` — the core. It scans the log incrementally,
  maintains per-agent reputation and suspicion, and applies the detection rules:
  fake/unassigned microtask claims, duplicate (replayed) evidence, self-donation,
  two- and three-node wash-trade cycles, linked collusive-endorsement clusters,
  and rug-pull / reward-redirection behavior. When an agent's suspicion crosses
  the threshold it is expelled, and the expulsion decision is itself appended to
  the signed log. A `pattern_detection` switch disables the cross-agent rules,
  used to isolate their contribution.
- `naive_reputation.py` — the weak baseline: mutable reputation that trusts
  self-reports and only expels after repeated direct defections.
- `beta_reputation.py` — a Beta-distribution reputation baseline for comparison.

**Recording surface and helpers**

- `live_scenario_schema.py` — the event/scenario data model, corpus validation,
  and `sanitized_event_for_agent()`, which strips evaluator-only ground-truth
  labels so the agent (and the estimator) only ever see observable structure.
- `event_gateway.py` — normalizes a live agent tool call into the canonical
  event, checks the tool/actor match, and never copies hidden labels into the
  log.
- `live_agent_tools.py` — the tool surface the live agent is given each step
  (claim microtask, donate, endorse, request benefit, redirect reward, …).
- `accountability.py`, `reputation.py`, `proxy.py`, `seedbox.py`,
  `bitcoin_anchor.py` — supporting domain model and an earlier standalone
  accountability monitor, kept for signed-log integration and migration tests.

## Evaluation

The evaluation isolates the two mechanisms that make recording trustworthy —
**log substrate** (mutable vs signed) and **cross-agent pattern reconstruction**
(off vs on) — by crossing them into four conditions:

| Condition | Log substrate | Pattern reconstruction |
|---|---|---|
| C0 naive reputation | mutable, no history | — |
| B1 rules over mutable log | mutable | on |
| B2 signed, no pattern | signed | off |
| C1 full system | signed | on |

Scenarios are **frozen**: each fixes which behavior is attempted, while the live
model only supplies the tool-calling path — so the comparison is about the
recording layer, not about whether a model chooses to attack. Two corpora are
used: a naive corpus (4 attack families × 3 intensities × 5 seeds = 60
scenarios) and adaptive corpora adding `threshold_aware`, `sybil_split`, and
`honest_dilution` strategies (40 scenarios each), the last of which include
deliberately ambiguous honest agents whose legitimate reciprocal behavior
*resembles* collusion, so wrongly expelling one counts as a measured false
positive.

To keep cost bounded, C0 and C1 are run live; B1 and B2 are reconstructed by
**replaying** recorded C1 evidence through differently-configured estimators —
no extra model calls.

- `generate_live_scenarios.py` — builds the frozen corpora.
- `live_orchestrator.py` — the live runner; entry point
  `python -m security.accountability_layer.evaluation.live_orchestrator`.
- `analysis_utils.py` / `rescore_logs.py` — the replay engine that produces the
  B1/B2/C1 ablation from recorded C1 logs.
- `sweep_thresholds.py` — replays the complete scenario stream across suspicion
  thresholds to trace the detection-vs-false-positive frontier and pick an
  operating point.
- `sq2_statistics.py` — survival analysis, significance tests, effect sizes, and
  confidence intervals.
- `evaluate_beta_baseline.py` — the Beta-reputation comparison.

A separate tamper experiment re-runs the naive corpus under B1 and C1 with an
injected adverse-history modification: B1 deletes its latest adverse mutable
entry; C1 modifies its latest signed entry.

## Results

**Naive corpus — detection and fallout.** The naive mutable baseline never
expelled the attacker; the full system expelled it in every scenario, far
sooner.

| Condition | Expelled | Mean reputation lag (events) | Mean fallout broadcasts | Mean fraudulent reputation gain |
|---|---:|---:|---:|---:|
| C0 naive reputation | 0 / 60 | 7.42 (censored) | 8.42 | 1.54 |
| C1 full system | 60 / 60 | 2.67 | 3.67 | 0.58 |

C1 cut mean fallout broadcasts by ~56% and fraudulent reputation gain by ~62%,
with no false positives on the naive corpus.

**Where detection comes from.** On clean histories B1 and C1 make identical
decisions — signing adds *integrity*, not extra detection. Disabling cross-agent
pattern reconstruction (B2) sharply weakened early detection (25% vs 100% of
primary attackers in the recorded-log ablation), confirming that linked-pattern
reconstruction drives the early catches.

**Integrity (tamper experiment, 120 trials).** Deleting an adverse entry
suppressed the mutable log's history in all 60 B1 scenarios with no cryptographic
trace; modifying a signed entry was detected by chain/signature verification in
all 60 C1 scenarios. This is the signed log's distinct contribution.

**Adaptive corpora — strength and boundary.** The full system held 100%
primary-attacker detection against `sybil_split` and `honest_dilution`; raising
the suspicion threshold from 5 to 6 removed the false positives caused by the
ambiguous honest agents while preserving detection. The `threshold_aware`
strategy, which spreads suspicious behavior across colluding identities so no
single one crosses a false-positive-safe threshold, evaded detection at every
such threshold — a genuine limitation of per-identity suspicion, and the clearest
direction for future work (group-level attribution).

## Running It

Generate the corpora (also done automatically by the runner):

```bash
python -m security.accountability_layer.evaluation.generate_live_scenarios \
  --out security/datasets/sq2_live_reputation_trap_scenarios.jsonl
```

Deterministic smoke (no model calls):

```bash
python -m security.accountability_layer.evaluation.live_orchestrator \
  --mode deterministic \
  --conditions C0_naive_reputation C1_vukzero_accountability \
  --limit 2 --out results/sq2_smoke
```

Full factorial + analysis, then the tamper experiment (require an
OpenAI-compatible endpoint):

```bash
bash security/accountability_layer/run_sq2_accountability_evaluation.sh
bash security/accountability_layer/run_sq2_tamper_experiment.sh
```

Offline analysis over a completed run (no model calls):

```bash
python -m security.accountability_layer.evaluation.rescore_logs    --run-dir <run> --out <analysis>
python -m security.accountability_layer.evaluation.sweep_thresholds --run-dir <run> --out <analysis>
python -m security.accountability_layer.evaluation.sq2_statistics   --trials <run>/sq2_trials.csv --out <analysis>
```

Each run exports `sq2_summary.json`, `sq2_run_metadata.json`, per-trial CSV/JSONL,
the `by_condition`/`by_family` lag and fallout tables, `sq2_log_integrity.csv`,
the `analysis/` artifacts, and the per-scenario signed evidence under
`trials/<condition>/<scenario>/accountability.log`.

## Tests

```bash
python -m pytest tests/test_subq2_*.py tests/test_signed_log.py tests/test_signed_verify.py -q
```

These cover the live harness end-to-end, the replay/ablation and threshold math,
the signed-log migration of the supporting modules, and the signed log's
sign-then-chain append and tamper detection.
