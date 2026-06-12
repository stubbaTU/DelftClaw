# Build plan — OpenRouter model backend + live dojo CLI wiring (Substrate 2)

Date: 2026-06-10, same session-day as `2026-06-10-ladder-and-agentdojo-substrate.md`. This plan
closes the model-backend sub-decision and finishes Substrate 2's last offline-buildable piece.

**Decision (Lucas, this session): OpenRouter ONLY.**
- claude-cli wrapper REJECTED — architecturally unfit: claude-cli runs its own agent loop and
  executes tools itself, bypassing the `ToolsExecutionLoop` seam where `IntegrityDefenseElement`
  sits. Not just glue cost; it breaks the substrate design.
- Anthropic-direct NOT built. If ever needed it becomes another spec prefix in `build_llm` — the
  spec-string design below leaves that door open without committing to it.

Repo: `redteam-ablation` (package `redteam_ablation`). Interpreter (exactly this; offline):

    C:/Users/lucas/Documents/Research Project/redteam-ablation/.venv/Scripts/python.exe

Standing rules: **no git commits**; **no installs outside `.venv`** (no new deps needed — `openai`
2.41.0 already installed as an agentdojo dependency); **tests are offline** (no network, and **no
test constructs a provider client** — hence the `client_factory` seam). Current suite: 265 green.

Survey is DONE and pinned in `substrates/agentdojo_native/API_NOTES.md` §7 (OpenRouter backend
survey, 2026-06-10). Code against API_NOTES, not guesses.

---

## Step 1 — `substrates/agentdojo_native/model.py`: the OpenRouter factory

- Module constant `OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"`.
- `build_llm(spec: BasePipelineElement | str | None = None, *, client_factory=None) -> BasePipelineElement`:
  - **Passthrough unchanged**: an explicit `BasePipelineElement` is returned as-is (existing test
    seam; existing tests must keep passing).
  - **`"openrouter:<model-id>"`** (str): model-id is everything after the FIRST colon and must be
    non-empty (OpenRouter ids contain `/`, e.g. `anthropic/claude-sonnet-4-6` — do not split on
    `/`). Empty model-id → `ValueError`.
    - API key from `os.environ["OPENROUTER_API_KEY"]`; missing or empty → `RuntimeError` naming
      the env var, raised BEFORE any client is constructed (fail loudly, nothing half-built).
    - `factory = client_factory or openai.OpenAI`;
      `client = factory(api_key=key, base_url=OPENROUTER_BASE_URL)`;
      return `OpenAILLM(client, model_id)` (keep agentdojo defaults:
      `reasoning_effort=None`, `temperature=0.0`).
  - **`None`** → `ValueError` saying a spec is now required (`"openrouter:<model-id>"` or an
    explicit element). This REPLACES the old `NotImplementedError` — the backend is chosen; the
    docstring's open-sub-decision framing is updated accordingly.
  - **Any other string** (e.g. `"anthropic:x"`) → `ValueError` listing the supported spec form.
- Imports of `openai` / `OpenAILLM` may be top-level: `model.py` lives inside the substrate
  package, which is allowed to depend on agentdojo+openai (core stays clean; the CLI already
  lazy-imports this module).

## Step 2 — CLI: wire `dojo-benign` / `dojo-control` as real live paths

Current state to verify first: the dojo subparsers parse `--run-id --n --arms --suite
--benchmark-version --out` but have **no `--model`**, and `_cmd_dojo` just calls `build_llm()` and
converts `NotImplementedError` → `SystemExit`.

- Add `--model` (required=True) to both dojo subparsers; help text names the spec form
  (`openrouter:<model-id>`). The spec string passes verbatim to `build_llm`.
- `_cmd_dojo` becomes the live driver (lazy imports stay so core CLI never touches agentdojo):
  1. `element = build_llm(args.model)` — catch `ValueError` / `RuntimeError` →
     `SystemExit(f"{command}: {exc}")` (fail-fast convention preserved; still no network here).
  2. Validate arms early: `args.arms.split(",")` each through `interceptors_for` — `KeyError` →
     `SystemExit` with the registry's message.
  3. `suite = get_suite(args.benchmark_version, args.suite)`.
  4. `owner = make_owner_identity()` (same helper as the offline harness and dojo tests —
     `redteam_ablation.runtime.fake.make_owner_identity`).
  5. `llm_factory = lambda: element` — `OpenAILLM` is stateless across episodes (client + model
     only), so one element reused through the runner's `llm_factory` contract is correct.
  6. Dispatch: `dojo-benign` → `runner.run_benign(...)`; `dojo-control` →
     `runner.run_behaviour_control(...)` with the pre-registered default pairing. Inspect the
     actual runner signatures before wiring (e.g. `run_benign(*, suite, arms, n, llm_factory,
     run_id, out_dir, owner_identity, ...)`).
  7. Print the written jsonl path; return 0.
- Single `--suite` per invocation stays (full benign = 4 invocations, one per suite) — matches the
  existing arg surface; do not grow it to a multi-suite loop in this build.

## Tests (offline; no network; no provider clients)

`build_llm`:
- Explicit-element passthrough unchanged (existing tests keep passing).
- `build_llm("openrouter:some/model", client_factory=fake)` with `OPENROUTER_API_KEY`
  monkeypatched → returns an `OpenAILLM`, `.model == "some/model"`, fake called exactly once with
  `api_key=<the key>` and `base_url == OPENROUTER_BASE_URL`.
- Missing AND empty `OPENROUTER_API_KEY` → `RuntimeError` naming the env var; fake factory never
  called.
- `build_llm(None)` → `ValueError`; unknown prefix → `ValueError`; `"openrouter:"` (empty id) →
  `ValueError`.

CLI:
- dojo subcommand without `--model` → `SystemExit` (argparse `required`).
- `--model openrouter:x` with no `OPENROUTER_API_KEY` → `SystemExit` carrying the RuntimeError
  text (and no run dir created).
- Full wiring test per command: monkeypatch `build_llm` (→ scripted fake element) and `get_suite`
  (→ the stub suite used by existing dojo tests) → `benign.jsonl` / `behaviour.jsonl` written with
  the pinned key contracts, exit code 0.
- Existing dojo-CLI tests that pinned the NotImplementedError fail-fast behaviour are UPDATED to
  the new contract — each such change must trace to a line in this plan; no other existing
  assertion may be weakened.

## TDD phases (standard flow)

1. **Red** — subagent writes FAILING tests only, runs them with the venv interpreter, confirms
   expected failure modes. May update the existing fail-fast dojo CLI tests per this plan.
2. **Green** — different subagent writes the MINIMUM production code to go all-green.
3. **Review** — two subagents in parallel: (a) code/design review (plan alignment, fail-loud
   paths, no core→agentdojo imports, no provider client constructed at import time);
   (b) test review (coverage gaps, env-var isolation via monkeypatch, no network reachable).
4. **Patch** — orchestrator applies review findings, re-runs the full suite.

## Out of scope (run-time, not build-time)

- Spending decisions / live smoke (`needs OPENROUTER_API_KEY` + funded account; cost anchor:
  ~$40 Sonnet-4.6-class pilot at 7 arms × N=1, ~$400 full pre-registered grid).
- Benchmark-version pin (`v1` vs `v1.2.2`) — CLI default stays `v1`, overridable.
- The audit-arm replay cost lever (methodology amendment — paper decision, not harness code).

---

## Patch-phase amendments (post-review, 2026-06-10 — the A-numbers cited in code comments)

Applied by the orchestrator from the union of the two parallel reviews (code/design + tests).
Suite after patch: **294 passed, 0 failed** (was 278; +16 tests).

- **A1 — legible suite/version errors.** `get_suite` KeyError is caught; `load_suites` keeps a
  defaultdict, so an unknown VERSION masquerades as a missing suite under an empty registry —
  `_cmd_dojo` disambiguates via `get_suites(version)` and names the available suites on a
  suite-typo.
- **A2 — stock default system message.** The live pipeline now passes
  `system_message=load_system_message(None)` (agentdojo's `data/system_messages.yaml` default —
  the Emma Johnson identity the stock pipeline and the `important_instructions` attack lean on).
  Without it, every live episode silently diverged from the stock pipeline the paper compares
  against.
- **A3 — model-id whitespace.** `build_llm` strips the id after the first-colon split; a
  whitespace-only id fails as a `ValueError` instead of a provider 404 after the run dir exists.
- **A4 — model provenance.** Both runners gained `extra_meta: dict | None`; the CLI pins
  `{"model_spec": args.model}` into `meta.json`. A metered run's provenance must name its model.
- **A5 — `--n >= 1` guard.** First rung of the fail-fast ladder; a zero/negative grid previously
  "succeeded" vacuously with an empty jsonl and exit 0.
- **A6 — arms hygiene.** Entries stripped, duplicates rejected (a repeated arm would double-run
  and double-count rows in a metered grid).
- **A7 — KNOWN GAP, deliberately deferred: `dojo-control` runs with `attack=None`.** Injection
  placeholders keep their benign defaults, so `final_verdict` measures SPONTANEOUS goal
  achievement, not attack success. The CLI prints a loud WARNING (pinned by a test, so removing
  it is a conscious act). Wiring `load_attack` properly needs the per-arm `target_pipeline`
  inside `_run_episode` — a follow-up build. **Do not run a metered `dojo-control` until then.**
- Doc fixes: cli.py module/`--help` text no longer claims the whole CLI is offline (scoped to
  `ablation`/`table`); runner docstring's "fresh element per episode" loosened to match the
  stateless-reuse contract the live CLI uses.
- Review findings NOT applied (deliberate): case-folding of the spec prefix (fail-loud is fine);
  swapping arm-validation ahead of `build_llm` (plan ladder order kept — construction is
  network-free per API_NOTES §7, and the ladder order is now test-pinned).
