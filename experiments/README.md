# SQ3 — Cross-compilation behavioural-reproduction & convergence harness

This package measures, for the markdown-as-overlay channel, whether independent
LLM compilations of the same protocol document end up **behaving** the same way —
not merely agreeing on the wire bytes, but taking the same actions in response to
them. It is built around a **hand-written reference implementation** of each
protocol, so behavioural reproduction is judged against a model-independent oracle
rather than against the model's own samples.

## The two arms

The study mirrors the two things the deployed agents actually do.

**Distribution (headline).** A genesis agent publishes a *fixed* descriptor
(`echo`, `content_community`, `payment_request`, `file_transfer`); peers compile
it independently and run it live to a goal. We reproduce that by compiling the
fixed descriptor many times across models/temperatures and scoring:

- **behavioural reproduction** — does one compilation reproduce the reference's
  behaviour across the scenario battery? `Conformance(C) = match(C,R) ∧ match(R,C)`,
  so the candidate is exercised as both the initiating and the responding side.
- **convergence** — do two *independent* compilations agree? `Interop(A,B) =
  match(A,B) ∧ match(B,A)`, reported split by **pairing**: `self` (same model)
  vs `cross` (different models — the heterogeneous case the real network runs).
- **compile outcomes** — `compile_load_fail` vs `compile_vector_fail` vs usable,
  kept distinct (infrastructure errors are isolated and never counted).
- **source diversity** — distinct sources / compiles, so a high convergence rate
  that is really "a source compared with itself" is visible.

**Authoring (secondary).** A model *authors* a new descriptor from a prose goal
(`genesis`) or by evolving a fixed base (`evolution`). With no human reference,
we score:

- **faithfulness** — a rule-based structural rubric over the parsed document
  (e.g. a file-transfer must declare a 32-byte hash field, a seq+data chunk
  message, and per-content transfer state), so a model cannot climb the ladder by
  under-specifying.
- **adoption convergence** — the author's compile and a *different* adopter
  model's compile must reach the same observable state on the document they both
  compiled (reference-free: each serves as the other's oracle).

## How behavioural reproduction is measured

Each protocol has a hand-written reference `Community` in `experiments/references/`,
sharing the descriptor's content-derived `community_id` and emitting
byte-identical wire frames. A *scenario* (`experiments/scenarios.py`) is a scripted
exercise in two tiers — a demo-faithful happy path plus an adversarial edge
battery (out-of-order + duplicate chunks, a corrupted chunk, a duplicate payment
request, an over-`MAX_RESULTS` search) — run on two/three live `MockIPv8` nodes
(`experiments/driver.py`). State is compared identity-aware and at full value
(`experiments/oracle.py::canonicalize`), judging only the handler-driven delta.

## Commands

```bash
# Wiring smoke test — 3 compiles of (distribution, echo, haiku, T=0).
python -m experiments.cli run --profile smoke

# Headline distribution factorial — 4 rung x 3 model x 3 temp x 20 = 720 compiles.
python -m experiments.cli run --profile distribution      # resume-safe

# Authoring factorial, or both arms.
python -m experiments.cli run --profile authoring
python -m experiments.cli run --profile full

# Offline scoring over the saved sources (no LLM):
python -m experiments.cli levels           # functional vs representational, self/cross -> levels.json
python -m experiments.cli temperature      # behavioural reproduction per temperature -> temperature.json
python -m experiments.cli authored-levels  # authored-protocol self/cross convergence -> authored_levels.json
python -m experiments.cli report           # render summary.md

python -m experiments.cli preflight  # 1 compile per model on echo — confirm ids resolve
python -m experiments.cli rungs      # list rungs + loaded specs
```

`run` needs a reachable LLM endpoint (`LLM_BASE_URL` / `LLM_API_KEY`; source
`configs/.env`, the local proxy on :11600 forwards to Anthropic). The scorers
(`levels`, `temperature`, `authored-levels`) and `report` are offline. Models
are pinned to the newest tier that still exposes the sampling-`temperature`
parameter (Opus 4.6, Sonnet 4.6, Haiku 4.5).

## Artifacts

```
results/<session>/
  runs.jsonl       # one line per compile/author trial (outcome + behavioural reproduction)
  sources/<rung>/<run_id>.py   # usable sources, for the offline scoring pass
  levels.json      # written by `levels`
  temperature.json # written by `temperature`
  authored_levels.json   # written by `authored-levels`
  summary.md       # rendered tables (after `report`)
```

Sessions are timestamped; a Ctrl-C'd run resumes the active one, then a new
session starts. Re-running the scorers / `report` is always safe.

## Layout

```
experiments/
  config.py        # arms, models, temps, profiles, self/cross pairing
  fixtures.py      # fixed-spec loading + fixture_sha
  references/      # hand-written reference Communities (the oracle)
  oracle.py        # scenario types, run_scenario, canonicalize + delta
  driver.py        # programmable N-node mock network
  scenarios.py     # per-rung Tier-1 demo path + Tier-2 edge battery
  outcomes.py      # compile outcome taxonomy + infra isolation
  conformance.py   # Conformance(C), Interop(A,B) against the reference
  authoring.py     # Flow-B document authoring (author_document)
  faithfulness.py  # Flow-B structural rubric
  adoption.py      # Flow-B reference-free adoption convergence
  distribution.py  # Flow-A compile + score helpers
  runner.py        # factorial orchestrator + pairing pass + sessions
  report.py        # JSONL -> summary.md
  cli.py           # argparse surface
```

`tests/test_sq3_*.py` cover the harness offline (no live LLM); the reference
self-consistency + negative-control gates in `test_sq3_oracle.py` /
`test_sq3_scenarios.py` are what make the oracle a sound, non-circular ground
truth.

## Threats to validity (write-up checklist)

- **Behavioural reproduction is judged against an author-written reference +
  author-written scenarios.** A second author or adversarially-drawn scenarios
  would strengthen construct validity (open item).
- **Behaviour, not just wire.** Wire agreement is near-tautological given the
  encoding tables; the battery targets the handler prose, where compilations
  diverge.
- **One change to the sandbox** (hashing + timestamps) widened ordinary
  computation the protocols need; the containment boundary was untouched, and a
  compile that reached past it was counted as a failure, not waved through.
- **Three Claude models, four protocols, three temperatures** bound external
  validity. State the scope.
