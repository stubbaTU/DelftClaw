# Build plan — Enforcement-mode ladder (shared core) + AgentDojo-native substrate (Track B)

Date: 2026-06-10. Architecture **Y (two substrates)**, per the locked decision of 2026-06-07.
This plan covers the **shared core** (task #10: enforcement-mode ladder + ALR predicate) and
**Substrate 2** (task #11: AgentDojo native). Substrate 1 (OpenClaw live wiring) is OUT of scope.

Repo: `redteam-ablation` (package `redteam_ablation`). Interpreter (use exactly this; offline):

    C:/Users/lucas/Documents/Research Project/redteam-ablation/.venv/Scripts/python.exe

Standing rules: **no git commits** (Lucas approves per-commit); **no pip installs outside `.venv`**;
**tests are offline** (no network, no provider clients constructed). Current suite: 158 tests green.

---

## Background (one paragraph each)

**Why the ladder.** The paper's variant set is now **7 arms**, not V0–V4: V0 (vanilla) +
P1-audit / P1-strict, P2-audit (audit by construction, no strict twin — the ≈0 floor),
P3-audit / P3-strict, ALL-strict. A variant is a named set of *mode-tagged* interceptors; mode is a
**branch-on-failure parameter** (audit = detect + allow; strict = deny), not new crypto. ASR and ALR
become two readings of the same audit↔strict axis: audit arms ⇒ ASR == V0, ALR ≈ 0; strict arms ⇒
ASR collapse in their column AND a measurable ALR. The headline utility quantity is the
**strict−audit ALR delta** per primitive.

**Why ALR + conditioning.** ALR (Availability-Loss Rate) = legitimate owner actions wrongly blocked /
legitimate actions that would have succeeded absent the control. The denominator conditioning on
**baseline (V0) task success** is mandatory — SOTA models fail many benign tasks anyway, and counting
capability failures as vetoes would fake the result. Both outcomes are pre-registered as valid
(ALR>0 = measured cost; ALR=0 = the shield is free on this workload).

**Why AgentDojo native (Substrate 2).** AgentDojo (NeurIPS 2024 D&B, MIT, `pip install agentdojo`)
runs in its OWN harness; our primitives plug in as a **single defense pipeline element** that builds a
`ToolDecision` per proposed call and runs it through the **same `Dispatcher`/interceptors** as the
offline harness. Its **97 benign user tasks** → ALR workload (in-task false-positive channel). The
**6 Workspace-suite injection tasks** → the Behaviour control column (expected NOT to move under our
integrity primitives — that flatness is the point: it proves integrity-specificity). Per F9:
12 attacks total (6 Shapira integrity on Substrate 1 + 6 AgentDojo behaviour here) × 7 arms × N=10.
Substrate 2 needs NO VPS, NO MCP, NO `run_episode`.

---

## Step 1 — Shared core: enforcement-mode ladder + ALR predicate

### 1.1 Interceptor `mode` parameter

- `OwnerAnchoredIdentityInterceptor` (P1) and `ConstitutionHashInterceptor` (P3) gain a keyword-only
  constructor param `mode: str` with values `"audit" | "strict"`. **Default `"strict"`** (preserves
  current fail-closed semantics for any existing direct instantiation; the registry always passes
  mode explicitly). Invalid mode → `ValueError` at construction (fail loudly).
- **Strict** = current behaviour: violation → `InterceptDecision(allow=False, reason=...)`.
- **Audit** = violation → `InterceptDecision(allow=True, flagged=True, reason="audit: ...")` —
  detect-and-proceed, never denies.
- `SignedLogAuditInterceptor` (P2) is audit by construction — **no mode param** (its asymmetry is
  intentional and stays).
- The interceptor `name` must carry the mode (e.g. `P1-owner-identity[audit]` vs
  `P1-owner-identity[strict]`) so `denied_by` / trace attribution is mode-unambiguous.

### 1.2 Audit-detection observability

The paper claims audit arms *detect* — detections must be visible in per-trial records:

- `InterceptDecision` gains `flagged: bool = False` (frozen dataclass; default keeps old call sites valid).
- `Dispatcher.dispatch` collects names of flagging interceptors during the inspect loop and records
  them on the `ExecutionResult` as a new field `flagged_by: tuple[str, ...] = ()` (our vendored copy
  of the contracts — document the extension in `VENDORED.md`).
- `FakeRuntime`'s trace dicts gain a `flagged_by` key (list) alongside the existing
  `proposed_tool/kwargs/allowed/executed/reason/interceptor` keys, so `trials.jsonl` carries
  detections via `tool_call_trace` with no schema change to `TRIAL_KEYS`.

### 1.3 Registry: 7 arms

In `interceptors/registry.py`:

- Canonical order:
  `ARM_ORDER = ["V0", "P1-audit", "P1-strict", "P2-audit", "P3-audit", "P3-strict", "ALL-strict"]`
- Composition (shared stateless singletons, mode-tagged):
  - `V0` = `[]`
  - `P1-audit` = `[P1(mode=audit)]` ; `P1-strict` = `[P1(mode=strict)]`
  - `P2-audit` = `[P2]`
  - `P3-audit` = `[P3(mode=audit)]` ; `P3-strict` = `[P3(mode=strict)]`
  - `ALL-strict` = `[P1(strict), P2, P3(strict)]` (same P1,P2,P3 order as old V4)
- **Legacy aliases kept** so old call sites/tests keep meaning: `V1`→P1-strict set, `V2`→P2-audit
  set, `V3`→P3-strict set, `V4`→ALL-strict set. `VARIANT_ORDER` is **re-pointed to `ARM_ORDER`**
  (the grid the runner/CLI iterate is the 7 arms). `interceptors_for` accepts arm names AND legacy
  aliases; unknown → `KeyError` listing known names.

### 1.4 Expected offline matrix (update the proven-matrix tests)

With the deterministic `FakeRuntime`, the predicted 7×5 shape that tests must pin:

- `P1-audit`, `P3-audit`, `P2-audit` rows **identical to V0** (audit never denies).
- `P1-strict` row == old V1 row (Identity column collapse); `P3-strict` == old V3 (Config collapse);
  `ALL-strict` == old V4 row.
- Audit arms' trials DO carry `flagged_by` entries exactly where the strict twin would have denied
  (the detection-mirror property — test it explicitly; it is the paper's audit-arm claim).

### 1.5 ALR predicate + aggregation — new module `redteam_ablation/metrics/alr.py`

Stdlib only. Operates on **benign trial records** (produced by any substrate; contract below).

- `owner_task_denied(tool_call_trace) -> bool` — True iff ≥1 trace step was denied by an
  interceptor (`allowed == False` and `interceptor` not None). Unknown-tool non-executions do NOT count.
- Channel taxonomy: records carry `channel: "in-task" | "maintenance-lockout"`. Everything this
  session produces is `"in-task"`; the lockout channel arrives with Substrate 1 lifecycle episodes.
  The aggregation must group by channel but not hardcode the in-task assumption.
- `alr_summary(records, baseline_arm="V0")` — per (arm, channel):
  `{n_eligible, denied, alr, wilson_low, wilson_high}` where **eligibility** of (task_id, trial_index)
  under arm X requires the SAME (task_id, trial_index) under `baseline_arm` to have
  `utility_success == True` (the non-circularity conditioning). Missing baseline record → that trial
  is ineligible (and counted in an explicit `n_unconditioned` so silent drops are visible).
  Reuse `metrics/wilson.wilson_interval`.
- `strict_audit_delta(summary, primitive)` — ALR(P1-strict) − ALR(P1-audit) etc.; returns the delta
  plus both arms' summaries (the headline quantity).

**Benign record contract** (pin as `BENIGN_TRIAL_KEYS`, mirroring `TRIAL_KEYS` style):
`run_id, suite, task_id, variant, trial_index, utility_success, denied, denied_by, flagged_by,
channel, tool_call_trace, wall_clock_seconds`. (`variant` keeps the same key name as attack trials
for aggregator consistency; `denied` is `owner_task_denied(trace)` precomputed.)

### 1.6 CLI / Makefile debt (decided 2026-06-07)

- CLI subcommand `phase-a` → **`ablation`** (keep `phase-a` as a working deprecated alias);
  **remove the `phase-b` stub** subcommand entirely (Phase B is cut from the paper).
- Makefile: `phase-a` target → `ablation` (alias `phase-a:` may remain pointing at it);
  **delete the `phase-b` target**; `smoke: ablation table`. Update README/Makefile help text.
- The runner keeps the name `run_phase_a` internally? **No** — rename to `run_ablation` with a
  module-level alias `run_phase_a = run_ablation` retained for old imports/tests.

---

## Step 2 — Substrate 2: AgentDojo native

**Survey first** (pre-Red): install `agentdojo` into `.venv`, then a read-only survey pins the
installed version + exact import paths/signatures into
`redteam_ablation/substrates/agentdojo_native/API_NOTES.md`. Everything below names APIs from the
paper summary — the survey CORRECTS this plan where the installed reality differs; Red/Green code
against API_NOTES.md, not against this plan's guesses.

### 2.1 Package layout

New subpackage `redteam_ablation/substrates/agentdojo_native/` (named to avoid confusion with the
`agentdojo` package itself):

- `defense.py` — `IntegrityDefenseElement`, an AgentDojo pipeline element wrapping tool execution
  (likely subclassing/replacing their tools-executor element; survey decides the exact seam).
- `runner.py` — benign + behaviour-control grid drivers writing contracted JSONL.
- `model.py` — model-backend factory. **Backend choice is DEFERRED** (Anthropic API vs OpenRouter vs
  claude-cli wrapper — Lucas decides later). Build model-agnostic against AgentDojo's own LLM
  pipeline-element abstraction; raise a clear `NotImplementedError("backend not chosen")` from the
  factory's default path. Tests use a scripted fake LLM element only.
- `API_NOTES.md` — survey output.
- Register the subpackage in `pyproject.toml` packages list. `agentdojo` is a dependency of the
  substrate ONLY — core modules must not import it; add to `requirements.txt` pinned, with a comment
  that core stays stdlib+crypto+yaml.

### 2.2 `IntegrityDefenseElement` semantics (the one-core-two-adapters rule)

- For EVERY tool call the model proposes: build
  `ToolDecision(tool_name=<fn>, tool_kwargs=<args>, sender_id=<owner>, reason=...)` and route it
  through the **shared `Dispatcher`** — the same class, same interceptors from
  `interceptors_for(arm)`. Tool execution happens via `Dispatcher.dispatch`: the dispatcher's
  `ToolPolicy` handlers **delegate to AgentDojo's runtime** (wrap each suite tool as a policy whose
  handler invokes the AgentDojo function with the env). This keeps dispatch as THE chokepoint and
  makes P2's `on_execute` signed-log append fire naturally.
- **Denied call** → do NOT execute; surface a structured denial as the tool's result/error message to
  the model (AgentDojo defense convention — episode continues, the model sees the denial). The denial
  must land in our trace with `denied_by`.
- **Context synthesis per episode**: `owner_id` == the session's sender (all AgentDojo calls are the
  owner's session, so P1 passes by construction on benign AND injection runs — that is exactly the
  orthogonality the Behaviour control is supposed to show); constitution session-hash == published
  hash (P3 passes); per-(run,arm) `signed_log_path` like the offline runner.
- Trace buffer: the element accumulates the same trace-dict shape as `EpisodeResult.tool_call_trace`
  (incl. `flagged_by`) so ALR/judging code is substrate-agnostic.

### 2.3 Runners + records

- `run_benign(suites, arms, n, out_dir, run_id, model)` — the 97 user tasks (all four suites) ×
  `ARM_ORDER` × N, **no attack loaded**, scored with the suite's own `utility(...)`; one JSONL line
  per trial with `BENIGN_TRIAL_KEYS` → `<out>/<run_id>/benign.jsonl`.
- `run_behaviour_control(arms, n, out_dir, run_id, model)` — the **6 Workspace injection tasks**;
  each injection task is ONE attack (F9 arithmetic: 6 × 7 × N). Each needs a (user-task, injection)
  pairing to execute: **pre-registered default = the lowest-numbered compatible user task** per
  injection task; the chosen pairing is recorded IN the output record (`paired_user_task`). Scored
  with the suite's `security(...)`; records mirror the attack-trial shape (`variant, attack_id,
  attack_class="Behaviour", trial_index, security_success → final_verdict, tool_call_trace, ...`)
  so `metrics/aggregate.aggregate_run` can consume them unchanged where possible.
- N=10 with a real LLM is sampling-based (no seed honoring by providers) — `trial_index` is the
  replicate label; no fake determinism claims.
- CLI: new subcommands `dojo-benign` and `dojo-control` (live paths; require an explicit
  `--model ...` once the backend lands — for now they exist, parse args, and fail fast with the
  NotImplementedError from `model.py` unless given the fake element under test).

### 2.4 What tests cover (offline, no network)

- Defense element with a **scripted fake LLM element + a tiny stub suite** (2–3 toy tools/tasks
  registered via AgentDojo's own extension API, or a hand-built FunctionsRuntime if simpler per
  survey): every proposed call hits the Dispatcher exactly once; strict-arm denial does not execute
  the tool and surfaces the denial result; audit arm executes + flags; P2 appends to the signed log
  (verify roundtrip with existing verifier); trace shape matches contract.
- Benign runner with the stub suite: record schema == `BENIGN_TRIAL_KEYS`; utility result captured;
  ALR pipeline end-to-end on synthetic records (strict denies a call V0 succeeded on → ALR counts it;
  V0-failed task → ineligible).
- Behaviour runner: pairing recorded; `aggregate_run` consumes the records.
- NO test constructs a provider client or touches the network. `agentdojo` imports are allowed.

---

## TDD phases (the standard flow — subagents inherit these roles)

Run Step 1 fully, then Step 2 (Step 2's Red needs the survey + Step 1's registry/ALR names).

1. **Red** — a subagent writes FAILING tests only (no production code), runs them with the venv
   interpreter, and confirms they fail with the expected error modes (`ImportError`/`AttributeError`/
   assertion). It MAY update existing tests whose pinned expectations the spec changes (e.g.
   5-variant grid → 7 arms, matrix-shape tests per §1.4) — each such change must trace to a line in
   this plan. It must NOT weaken any existing assertion otherwise.
2. **Green** — a different subagent reads the failing tests + this plan and writes the MINIMUM
   production code to make the whole suite pass. No new tests; no refactors beyond need.
3. **Review** — TWO subagents in parallel: (a) code reviewer — design, security, edge cases, plan
   alignment, accidental core→agentdojo imports; (b) test reviewer — coverage gaps, missing
   parametrise axes (mode × primitive, arm aliases), failure-mode mirror coverage (each strict-deny
   test has an audit-flag twin).
4. **Patch** — the orchestrator applies the union of review findings as targeted edits and re-runs
   the suite.

## Open sub-decisions (flagged, not blockers)

- **Model backend for Substrate 2** — deferred by Lucas (2026-06-07 + reconfirmed). Build is
  backend-agnostic; the run is gated on this choice (metered cost ~$4 / 97 benign tasks / arm on
  GPT-4o-class — ×7 arms ×N, so budget matters).
- **Injection↔user-task pairing rule** — pre-registered default above; Lucas can override before any
  metered run.
- **Bulat/Johan gut-check (was Mon 2026-06-08)** — outcome not in the brain. Build proceeds on
  Lucas's instruction; if the gut-check changed scope, this plan adjusts.
