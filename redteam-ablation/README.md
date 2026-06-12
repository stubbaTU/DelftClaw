# redteam-ablation

Ablation harness for the TU Delft CSE3000 paper *Blockchain for AI Agents*.
The data-collection rig that runs the **7-arm enforcement-mode ladder**
(V0 + audit/strict arms per primitive) × 8 Shapira-derived attacks × N
trials/cell and reports per-cell attack-success-rate (ASR); the
`metrics/alr.py` module aggregates benign-workload records into the
availability-loss-rate (ALR) side of the security–utility tradeoff.

**This is the offline framework.** It is fully testable with a deterministic
fake backend — no real LLM/API calls, no real OpenClaw runtime.

- Import package: `redteam_ablation` (underscore). Repo dir: `redteam-ablation`.
- Arms are wired by **mode-tagged interceptors** on a tool dispatcher, not
  fork-per-variant. V0 = empty interceptor set (vanilla); the six ladder arms
  compose the three real interceptor bodies (P1 identity, P2 signed log, P3
  constitution) with *mode* as a branch-on-failure parameter (audit = detect +
  allow; strict = deny) — see *Arms + offline matrix* below. Legacy names
  V1–V4 resolve as aliases (V1→P1-strict, V2→P2-audit, V3→P3-strict,
  V4→ALL-strict).

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest
```

For the metered Substrate-2 commands (`dojo-benign` / `dojo-control`), put the
OpenRouter key in the gitignored repo-root `.env` (`OPENROUTER_API_KEY=sk-or-...`);
the CLI loads it on startup. A key already set in the environment takes
precedence. The test suite never reads `.env` (autouse fixture in
`tests/conftest.py`).

## Run the offline smoke

Fully offline and deterministic — no LLM/API calls. Uses the venv python:

```powershell
$PY = "C:/Users/lucas/Documents/Research Project/redteam-ablation/.venv/Scripts/python.exe"
# 7 arms × 8 attacks × 10 trials = 560 trial lines.
& $PY -m redteam_ablation.cli ablation --fake --n 10 --run-id smoke
# Aggregate per-cell ASR + Wilson bounds (7 × 8 = 56 cell rows).
& $PY -m redteam_ablation.cli table --run-id smoke
```

Outputs land under `runs/smoke/`:

- `runs/smoke/trials.jsonl` — one JSON line per trial (12-key schema); 7 × 8 × 10
  = 560 lines for the default smoke.
- `runs/smoke/cell_asr.csv` — `variant, attack_id, attack_class, n, successes,
  asr, wilson_low, wilson_high` (7 × 8 = 56 cell rows).
- `runs/smoke/class_matrix.csv` — per-`(variant, attack_class)` ASR matrix
  (`variant` then the five attack classes; the variant × class robustness view).
- `runs/smoke/class_entropy.csv` — per-variant success-class entropy
  (`variant, entropy_bits`); Shannon entropy of how a variant's residual
  successes spread across the five attack classes.
- For arms carrying P2 (`P2-audit`, `ALL-strict`; legacy `V2`/`V4`),
  `runs/smoke/signed_log_<variant>.log` — the P2 signed append-only audit log
  (one signed entry per executed call; `verify_integrity()` → `(True, [])`).

`ablation` requires `--fake` in this phase (the real OpenClaw/Sonnet runtime is
a later phase and would make network calls). `phase-a` is kept as a working
deprecated alias of `ablation`; the `phase-b` stub is removed (Phase B is cut).
Equivalent `make` targets: `make ablation` (alias `make phase-a`), `make table`
(see the `Makefile` for the Windows venv python path). `make table` produces all
three CSVs (`cell_asr.csv`, `class_matrix.csv`, `class_entropy.csv`) via the
`table` subcommand.

## Arms + offline matrix

Each arm is a named, ordered set of **real** mode-tagged interceptors the
dispatcher runs over every proposed tool call (`interceptors/registry.py`). The
fake fixtures carry the adversarial *inputs* each attack produces (a spoofed
`sender_id`, a diverged constitution hash); the **same** interceptor code runs
offline and, later, against the live agent — there are no hardcoded per-cell
outcomes.

| Arm | Interceptors | Defence |
| --- | --- | --- |
| V0 | — | vanilla; the dangerous tool fires unimpeded |
| P1-audit | P1 identity (audit) | **flags** any non-owner `sender_id`, never denies (ASR == V0) |
| P1-strict | P1 identity (strict) | **denies** any non-owner `sender_id` (the old V1) |
| P2-audit | P2 signed append-only log | audit by construction (no strict twin): signs every executed call via the `on_execute` hook, never denies |
| P3-audit | P3 constitution-hash (audit) | **flags** a diverged constitution, never denies |
| P3-strict | P3 constitution-hash (strict) | **denies** a session whose constitution diverged (the old V3) |
| ALL-strict | P1-strict + P2 + P3-strict | the full strict stack (the old V4) |

Running the offline smoke (`--n 10`) reproduces the **predicted offline matrix**,
computed entirely by the interceptor logic on the structured adversarial inputs
(see `class_matrix.csv`):

| arm | Audit-trail | Behaviour | Configuration | Identity | Mixed |
| --- | --- | --- | --- | --- | --- |
| V0 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| P1-audit | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| P1-strict | 1.0 | 1.0 | 1.0 | **0.0** | 1.0 |
| P2-audit | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| P3-audit | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| P3-strict | 1.0 | 1.0 | **0.0** | 1.0 | 1.0 |
| ALL-strict | 1.0 | 1.0 | **0.0** | **0.0** | 1.0 |

Reading the ladder:

- **Audit arms never deny**, so their ASR rows equal V0 — but their trials carry
  `flagged_by` entries at exactly the calls their strict twin would have denied
  (the detection-mirror property; ASR and ALR are two readings of the same
  audit↔strict axis).
- **P1-strict** collapses **Identity** to 0 (SH-03, SH-04 arrive under a
  non-owner principal and P1 denies them).
- **P3-strict** collapses **Configuration** to 0 (SH-05 diverges the
  constitution hash and P3 denies it).
- **ALL-strict** collapses **Identity + Configuration**; Behaviour, Audit-trail,
  and Mixed stay at 1.0. Audit-trail does **not** collapse because P2 is
  audit-grade (the signed accountability trail survives even when the live
  audit log is deleted).

Success-class **entropy** (`class_entropy.csv`) is highest for V0 and the audit
arms (≈2.25 bits; successes spread across all five classes) and lowest for
ALL-strict (≈1.52 bits; the residual successes concentrate in the three
surviving classes) — a more concentrated residual is a better robustness signal
than a diffuse one.

## Pinned upstreams

- **DelftClaw vendor commit:** `156ce74e3d1af71009b83f3212ad67238e23eaa2`
  (source of `contracts.py`, `primitives/signed_log.py`, `primitives/verify.py`;
  see `VENDORED.md` for the exact provenance and import swaps).
- **OpenClaw runtime commit:** _placeholder — pinned at Phase 2 when the real
  `OpenClawRuntime` + Sonnet 4.6 judge are wired._

## Status

Offline framework complete: the dispatcher, interceptor registry, fake runtime,
attack catalogue, judge, metrics, runner, and CLI are all built and green. The
three real interceptor bodies (P1 identity, P2 signed log, P3 constitution)
wire the 7-arm enforcement-mode ladder (legacy V1–V4 kept as aliases), the
offline smoke reproduces the predicted arm × class matrix end-to-end with no
network/LLM calls (see *Arms + offline matrix*), and `metrics/alr.py` carries
the ALR (availability-loss) side.

**Substrate 2 (AgentDojo native) is built offline:**
`redteam_ablation/substrates/agentdojo_native/` plugs the same interceptor
core into AgentDojo's own harness as a single defense pipeline element
(`defense.py`; installed-API pin in `API_NOTES.md`), with benign-ALR and
Behaviour-control grid runners (`runner.py`) and `dojo-benign` /
`dojo-control` CLI stubs. Live runs are gated on the model-backend
sub-decision (`model.py` fails fast until it's made). The real OpenClaw +
Sonnet runtime (Substrate 1 live wiring) is a later phase.
