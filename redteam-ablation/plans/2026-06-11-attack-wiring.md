# 2026-06-11 — Attack wiring for dojo-control (closes review A7)

Wire agentdojo's stock `load_attack` into `run_behaviour_control` so `final_verdict`
measures attack success, not spontaneous goal achievement. Approved plan; standard
TDD-with-subagents flow (Red → Green → parallel review → patch).

## Design pins

1. **Stock attacks crash on our pipeline names.** `ImportantInstructionsAttack.__init__`
   → `get_model_name_from_pipeline` (agentdojo `base_attacks.py:128-147`) raises
   `ValueError` unless `pipeline.name` CONTAINS a stock `MODEL_NAMES` key
   (`models.py:91`). Neither `redteam-ablation/{arm}` nor OpenRouter ids match.
   **Resolution:** `resolve_attack_model_alias(spec)` in `model.py` maps the model
   family to a representative stock key (`claude`/`anthropic` →
   `claude-3-7-sonnet-20250219` → prose "Claude"; `gpt`/`openai` →
   `gpt-4o-2024-05-13` → "GPT-4"; unknown → ValueError). The alias is embedded in
   the pipeline name (`redteam-ablation/{arm}/{alias}`); the REAL spec stays in
   `meta.json`. Attack classes stay 100% stock (same fidelity value as A2).

2. **Injections are arm-invariant** — the attack reads `target_pipeline` only for
   `.name`. So: load the attack ONCE per run and precompute `injections_by_id` for
   all injection tasks BEFORE `run_dir.mkdir` / file open. Fail-fast-before-write:
   registry KeyError, model-name ValueError, and "not injectable" ValueError all
   fire before anything is written. This deliberately deviates from the review
   note's literal "per-arm inside `_run_episode`" (which would re-run
   ground-truth candidate discovery 420× for byte-identical output and could only
   fail after the first row was written). Documented in the runner docstring.

3. **Load target:** a minimal `AgentPipeline([])` named
   `redteam-ablation/{arms[0]}/{alias}` — `load_attack` reads only `.name`;
   `arms[0]` is representative because injections are arm-invariant.

4. **Seam:** `attack_loader` parameter on `run_behaviour_control` (default =
   lazily-imported real `load_attack`), mirroring the `build_llm(client_factory=…)`
   idiom. Needed because real `BaseAttack.__init__` reads `injection_vectors.yaml`
   from disk — the offline stub suite has none, so tests inject a fake loader.

5. **Param change:** the dead `attack: Any | None` object param on
   `run_behaviour_control` (no caller ever passed it) is REPLACED by
   `attack_name: str | None = None` + `model_alias: str | None = None`.
   `attack_name=None` keeps the offline/scripted mode byte-identical (empty
   injections, unchanged pipeline name). `run_benign` untouched.

6. **CLI:** `--attack` on dojo-control ONLY (default `important_instructions`,
   the headline attack per API_NOTES §5); dojo-benign rejects it via argparse.
   Ladder gains rung 5 (alias resolution) and rung 6 (attack-name validation
   against the populated `ATTACKS` registry) AFTER the suite rung — existing
   fail-fast ordering tests keep their pins. The A7 WARNING is removed
   (conscious test update) and replaced by an informational line. Runner-raised
   ValueError ("not injectable") wraps to `SystemExit(f"{command}: …")`.

7. **meta.json** gains `"attack"` (loaded attack's `.name`) and `"model_alias"`.
   `BEHAVIOUR_TRIAL_KEYS` (11 keys) unchanged.

8. `is_dos_attack` is irrelevant to our pairing-driven runner (it only alters
   agentdojo's own benchmark iteration) — docstring note, no branch.

## TDD roles

- **Red:** failing tests — alias resolution (claude/gpt/unknown + round-trip
  through stock `get_model_name_from_pipeline`), runner loader-seam threading,
  attack_name=None preservation, not-injectable-fails-before-write, meta
  attack+alias, CLI unknown-attack / unknown-family fail-fast + ordering,
  dojo-benign rejects --attack, rewrite of `test_dojo_control_live_wiring`
  (warning assertions OUT, meta assertions updated, loader-call pinned).
- **Green:** minimal `resolve_attack_model_alias` + runner threading + CLI rungs.
- **Review (parallel ×2):** code/design fidelity; test quality (no network,
  env isolation, seam correctness).
- **Patch:** orchestrator applies the union.

## Verification

Full suite from repo root: `.venv/Scripts/python.exe -m pytest -q` — expect
294 → ~305 green, 0 failed. NO metered run (no OPENROUTER_API_KEY yet); future
$-smoke: `dojo-control --model openrouter:anthropic/claude-sonnet-4-6 --arms V0
--n 1`. NO commits without explicit approval.
