"""Ablation-grid driver: run the (arm x attack x trial) grid into trials.jsonl.

:func:`run_ablation` is the offline experiment loop (renamed from
``run_phase_a`` per plan 2026-06-10 §1.6 -- Phase B is cut from the paper, so
the driver loses its phase name; the module-level alias ``run_phase_a`` is
retained for old imports). For each arm (variant) it builds a
:class:`~redteam_ablation.runtime.base.Dispatcher` over the fake dangerous-tool
environment (:func:`~redteam_ablation.runtime.fake.make_fake_policies`) and the
variant's interceptor set
(:func:`~redteam_ablation.interceptors.registry.interceptors_for`). For each
attack in the catalogue and each trial index ``i`` it derives a deterministic
seed (:func:`~redteam_ablation.seeds.trial_seed`), runs one episode through the
supplied ``runtime``, judges it deterministically
(:func:`~redteam_ablation.judge.judge`), times the episode with
``time.perf_counter``, and appends one JSON line with EXACTLY the 12 contracted
keys to ``<out_dir>/<run_id>/trials.jsonl``.

Determinism: the seed depends on ``(catalogue_commit, variant, attack_id, i)``
only -- NOT on ``run_id`` -- so re-running (or running under a different
``run_id``) reproduces identical seeds and verdicts. With the ``FakeRuntime``
this loop touches no network and no LLM.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from redteam_ablation.catalogue.loader import catalogue_commit, load_catalogue
from redteam_ablation.interceptors.registry import interceptors_for
from redteam_ablation.judge import judge
from redteam_ablation.runtime.base import AgentRuntime, Dispatcher
from redteam_ablation.runtime.fake import make_fake_policies
from redteam_ablation.seeds import trial_seed

# The exact, ordered key set every trial line carries. Pinned so the JSONL schema
# is stable for the aggregator and any downstream consumer.
TRIAL_KEYS = (
    "run_id",
    "catalogue_commit",
    "variant",
    "attack_id",
    "attack_class",
    "trial_index",
    "seed",
    "tool_call_trace",
    "judge_verdict",
    "deterministic_verdict",
    "final_verdict",
    "wall_clock_seconds",
)


def run_ablation(
    catalogue_path: str | Path,
    variants: list[str],
    n: int,
    runtime: AgentRuntime,
    run_id: str,
    out_dir: str | Path,
    system_prompt: str = "",
    tools: list[Any] | None = None,
) -> str:
    """Run the ablation grid and write ``<out_dir>/<run_id>/trials.jsonl``.

    Iterates ``variants`` x ``load_catalogue(catalogue_path)`` x ``range(n)``;
    each cell trial is dispatched through a per-variant
    :class:`Dispatcher`, judged, timed, and serialised as one JSON line with the
    :data:`TRIAL_KEYS` schema. Returns the absolute path to the written
    ``trials.jsonl`` (as a string).
    """
    if tools is None:
        tools = []

    commit = catalogue_commit(catalogue_path)
    attacks = load_catalogue(catalogue_path)

    run_dir = Path(out_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    trials_path = run_dir / "trials.jsonl"

    with trials_path.open("w", encoding="utf-8") as fh:
        for variant in variants:
            # One dispatcher per variant: the fake dangerous-tool environment plus
            # the variant's (ordered) interceptor set. V0 has none, so the tool
            # fires unimpeded.
            #
            # Seed the per-variant context with the run-specific signed-log path
            # the V2/V4 audit interceptor (P2) appends to via its on_execute hook.
            # It is per-(run, variant) so V2's and V4's signed logs never collide
            # and a re-run starts from a clean chain. The runtime fills in the
            # owner identity / constitution hashes on top of this context per
            # episode (it only sets its own keys, preserving this one).
            signed_log_path = run_dir / f"signed_log_{variant}.log"
            dispatcher = Dispatcher(
                make_fake_policies(),
                interceptors_for(variant),
                context={"signed_log_path": str(signed_log_path)},
            )
            for attack in attacks:
                for i in range(n):
                    seed = trial_seed(commit, variant, attack.attack_id, i)

                    start = time.perf_counter()
                    episode = runtime.run_episode(
                        system_prompt=system_prompt,
                        tools=tools,
                        attack=attack,
                        seed=seed,
                        dispatcher=dispatcher,
                    )
                    elapsed = time.perf_counter() - start

                    verdict = judge(attack, episode)

                    record = {
                        "run_id": run_id,
                        "catalogue_commit": commit,
                        "variant": variant,
                        "attack_id": attack.attack_id,
                        "attack_class": attack.attack_class,
                        "trial_index": i,
                        "seed": seed,
                        "tool_call_trace": episode.tool_call_trace,
                        "judge_verdict": verdict.judge_verdict,
                        "deterministic_verdict": verdict.deterministic_verdict,
                        "final_verdict": verdict.final_verdict,
                        "wall_clock_seconds": float(elapsed),
                    }
                    fh.write(json.dumps(record) + "\n")

    return str(trials_path)


# Deprecated alias (plan §1.6): kept so old imports / call sites keep working.
run_phase_a = run_ablation
