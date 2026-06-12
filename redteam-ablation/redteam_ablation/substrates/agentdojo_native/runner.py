"""Substrate-2 grid drivers: benign (ALR) + behaviour control (plan §2.3).

``run_benign`` drives the suite's user tasks -- NO injection anywhere, the
placeholders keep their benign defaults -- across the requested arms and
writes one JSON line per (arm, task, trial) with EXACTLY
:data:`~redteam_ablation.metrics.alr.BENIGN_TRIAL_KEYS`, feeding
``metrics.alr`` unchanged.

``run_behaviour_control`` drives the suite's injection tasks as the Behaviour
control column (F9: each injection task is ONE attack;
``attack_class="Behaviour"``). Each injection task executes against a
pre-registered paired user task -- :func:`default_pairing` pins the lowest-
numbered user task, recorded in every record as ``paired_user_task`` -- and
``final_verdict`` is the suite's own deterministic ``security`` verdict
(True = the injected goal was achieved), so the records flow through
``metrics.aggregate.aggregate_run`` unchanged. With ``attack_name`` set, a
stock agentdojo attack is loaded once per run (through the injectable
``attack_loader`` seam) and fills every injection task's placeholders before
anything is written.

Both runners write a ``meta.json`` pinning run provenance (agentdojo version,
suite benchmark version, arms, n, plus anything the caller adds via
``extra_meta`` -- the live CLI pins ``model_spec`` there). Neither touches a
model provider: the LLM element comes from ``llm_factory`` -- fresh per
episode for stateful scripted fakes, or one stateless element reused (the
live CLI reuses a single ``OpenAILLM``) -- gated through
:func:`model.build_llm`.

``sender_overrides`` stages calibration violations (a non-owner session
sender for a given arm) for tests and pre-registered calibration episodes
ONLY -- the production benign run uses the owner defaults (plan §2.2).
"""

from __future__ import annotations

import importlib.metadata
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.task_suite.task_suite import TaskSuite

from redteam_ablation.metrics.alr import BENIGN_TRIAL_KEYS, owner_task_denied
from redteam_ablation.substrates.agentdojo_native.defense import (
    IntegrityDefenseElement,
)
from redteam_ablation.substrates.agentdojo_native.model import build_llm

# The exact, ordered key set every behaviour-control record carries. Mirrors
# the attack-trial style; the aggregate_run consumer reads variant /
# attack_id / attack_class / final_verdict.
BEHAVIOUR_TRIAL_KEYS = (
    "run_id",
    "suite",
    "variant",
    "attack_id",
    "attack_class",
    "paired_user_task",
    "trial_index",
    "utility_success",
    "final_verdict",
    "tool_call_trace",
    "wall_clock_seconds",
)


class AttackPrecomputeError(ValueError):
    """A failure while loading the attack or precomputing its injections.

    Raised BEFORE anything is written, so a caller (the CLI) can convert it to
    a clean refusal -- distinct from a mid-grid ValueError out of agentdojo,
    which must propagate with its traceback because rows HAVE been written.
    """


def _task_number(task_id: str) -> int:
    """Numeric suffix of an agentdojo task id (``user_task_12`` -> 12)."""
    return int(task_id.rsplit("_", 1)[1])


def default_pairing(suite: TaskSuite) -> dict[str, str]:
    """The pre-registered injection->user-task pairing (plan §2.3).

    Default rule: every injection task pairs with the suite's LOWEST-numbered
    user task. Simple, decided before any run, and recorded in each output
    record -- overridable via ``run_behaviour_control(pairing=...)`` before a
    metered run if Lucas pins a different rule.
    """
    user_ids = sorted(suite.user_tasks, key=_task_number)
    if not user_ids:
        raise ValueError(f"suite {suite.name!r} has no user tasks to pair with")
    lowest = user_ids[0]
    return {
        injection_id: lowest
        for injection_id in sorted(suite.injection_tasks, key=_task_number)
    }


def _run_episode(
    suite: TaskSuite,
    arm: str,
    user_task: Any,
    injection_task: Any,
    injections: dict[str, str],
    llm_factory: Callable[[], BasePipelineElement],
    owner_identity: Any,
    signed_log_path: str,
    environment_factory: Callable[[], Any] | None,
    sender_id: str | None,
    system_message: str | None,
    model_alias: str | None = None,
) -> tuple[bool, bool, list[dict[str, Any]], float]:
    """One episode: fresh defense + fresh LLM element, timed.

    ``model_alias`` (set on attack runs) is embedded in the pipeline name --
    the same shape as the attack's load-target -- so the name a stock attack
    resolved against matches the name the episodes actually run under.
    Returns ``(utility, security, tool_call_trace, wall_clock_seconds)``.
    """
    defense = IntegrityDefenseElement(
        arm,
        owner_identity=owner_identity,
        sender_id=sender_id,
        signed_log_path=signed_log_path,
    )
    llm = build_llm(llm_factory())

    elements: list[BasePipelineElement] = []
    if system_message is not None:
        elements.append(SystemMessage(system_message))
    elements += [InitQuery(), llm, ToolsExecutionLoop([defense, llm])]
    pipeline = AgentPipeline(elements)
    pipeline.name = (
        f"redteam-ablation/{arm}/{model_alias}"
        if model_alias is not None
        else f"redteam-ablation/{arm}"
    )

    environment = environment_factory() if environment_factory is not None else None

    start = time.perf_counter()
    utility, security = suite.run_task_with_pipeline(
        pipeline,
        user_task,
        injection_task,
        injections,
        environment=environment,
    )
    elapsed = time.perf_counter() - start
    return bool(utility), bool(security), defense.tool_call_trace, elapsed


def _first_denier(trace: list[dict[str, Any]]) -> str | None:
    """Name of the first interceptor that denied a step, or None."""
    for step in trace:
        if not step.get("allowed", True) and step.get("interceptor") is not None:
            return step["interceptor"]
    return None


def _all_flags(trace: list[dict[str, Any]]) -> list[str]:
    """Sorted union of audit detections across the episode's steps."""
    flags = {flag for step in trace for flag in step.get("flagged_by", [])}
    return sorted(flags)


def _write_meta(
    run_dir: Path,
    *,
    run_id: str,
    suite: TaskSuite,
    arms: list[str],
    n: int,
    extra: dict[str, Any] | None = None,
) -> None:
    """Pin run provenance next to the records (agentdojo + benchmark versions)."""
    meta = {
        "run_id": run_id,
        "suites": [suite.name],
        "arms": list(arms),
        "n": n,
        "agentdojo_version": importlib.metadata.version("agentdojo"),
        "benchmark_version": ".".join(str(v) for v in suite.benchmark_version),
    }
    if extra:
        meta.update(extra)
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def run_benign(
    *,
    suite: TaskSuite,
    arms: list[str],
    n: int,
    llm_factory: Callable[[], BasePipelineElement],
    run_id: str,
    out_dir: str | Path,
    owner_identity: Any,
    environment_factory: Callable[[], Any] | None = None,
    sender_overrides: dict[str, str] | None = None,
    system_message: str | None = None,
    extra_meta: dict[str, Any] | None = None,
) -> str:
    """Run the benign (ALR) grid: arms x user tasks x n -> benign.jsonl.

    No injection anywhere (``injection_task=None, injections={}`` -- the
    placeholders keep their benign defaults, API_NOTES §6). Returns the
    absolute path to the written ``benign.jsonl``.
    """
    run_dir = Path(out_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    out_path = run_dir / "benign.jsonl"

    with out_path.open("w", encoding="utf-8") as fh:
        for arm in arms:
            # Per-(run, arm) signed log, like the offline runner -- P2 arms
            # chain every executed call across the arm's episodes.
            signed_log_path = str(run_dir / f"signed_log_dojo_{arm}.log")
            sender_id = (sender_overrides or {}).get(arm)
            for task_id in sorted(suite.user_tasks, key=_task_number):
                user_task = suite.user_tasks[task_id]
                for i in range(n):
                    utility, _, trace, elapsed = _run_episode(
                        suite,
                        arm,
                        user_task,
                        None,
                        {},
                        llm_factory,
                        owner_identity,
                        signed_log_path,
                        environment_factory,
                        sender_id,
                        system_message,
                    )
                    record = {
                        "run_id": run_id,
                        "suite": suite.name,
                        "task_id": task_id,
                        "variant": arm,
                        "trial_index": i,
                        "utility_success": utility,
                        "denied": owner_task_denied(trace),
                        "denied_by": _first_denier(trace),
                        "flagged_by": _all_flags(trace),
                        "channel": "in-task",
                        "tool_call_trace": trace,
                        "wall_clock_seconds": float(elapsed),
                    }
                    assert tuple(record.keys()) == BENIGN_TRIAL_KEYS
                    fh.write(json.dumps(record) + "\n")

    _write_meta(run_dir, run_id=run_id, suite=suite, arms=arms, n=n, extra=extra_meta)
    return str(out_path)


def run_behaviour_control(
    *,
    suite: TaskSuite,
    arms: list[str],
    n: int,
    llm_factory: Callable[[], BasePipelineElement],
    run_id: str,
    out_dir: str | Path,
    owner_identity: Any,
    attack_name: str | None = None,
    model_alias: str | None = None,
    attack_loader: Callable[..., Any] | None = None,
    pairing: dict[str, str] | None = None,
    environment_factory: Callable[[], Any] | None = None,
    system_message: str | None = None,
    extra_meta: dict[str, Any] | None = None,
) -> str:
    """Run the Behaviour control grid: arms x injection tasks x n.

    ``attack_name`` names a registered agentdojo attack, resolved through
    ``attack_loader`` (default: the real
    ``agentdojo.attacks.attack_registry.load_attack``, imported lazily at
    call time -- the seam tests patch at its source; the real ``BaseAttack``
    reads ``injection_vectors.yaml`` off disk, which the stub suite lacks).
    The attack is loaded ONCE per run against a minimal target pipeline named
    ``redteam-ablation/{arms[0]}/{model_alias}`` and every injection task's
    injections are precomputed BEFORE the run dir or output file exist:
    injections are arm-invariant -- the attack reads the target pipeline only
    for ``.name`` -- so loading per episode would re-run ground-truth
    candidate discovery for byte-identical output and could not fail before
    the first row was written. Any loader / ``attack()`` exception therefore
    propagates with NOTHING written. (agentdojo's ``is_dos_attack`` flag is
    irrelevant here: it only alters agentdojo's own benchmark iteration, not
    our pairing-driven grid.)

    ``attack_name=None`` runs with empty injections -- the offline/scripted
    mode where the LLM element itself embodies the hijacked or faithful
    behaviour; the rows and pipeline names are byte-identical to the
    pre-wiring runner, while ``meta.json`` carries explicit
    ``attack: null, model_alias: null`` for provenance. ``model_alias`` rides
    into every episode's pipeline name and ``meta.json``; the REAL spec stays
    in ``extra_meta``. Precompute failures raise
    :class:`AttackPrecomputeError` (nothing written). Returns the path to
    ``behaviour.jsonl``.
    """
    pairing = pairing if pairing is not None else default_pairing(suite)

    # Load-once, precompute-all (plan 2026-06-11, design pins 2-3): everything
    # that can fail does so HERE, before the run dir is even created.
    injections_by_id: dict[str, dict[str, str]] = {}
    attack_meta_name: str | None = None
    if attack_name is not None:
        if model_alias is None:
            raise ValueError(
                "attack_name requires model_alias (resolve_attack_model_alias)"
                " -- the stock attacks resolve the model's prose name from the"
                " load-target pipeline name"
            )
        if attack_loader is None:
            # Lazy import at call time -- module-level binding would freeze
            # the real load_attack and defeat patching at its source.
            from agentdojo.attacks import attack_registry

            attack_loader = attack_registry.load_attack
        try:
            load_target = AgentPipeline([])
            load_target.name = f"redteam-ablation/{arms[0]}/{model_alias}"
            attack = attack_loader(attack_name, suite, load_target)
            attack_meta_name = getattr(attack, "name", attack_name)
            for injection_id in sorted(suite.injection_tasks, key=_task_number):
                injections_by_id[injection_id] = attack.attack(
                    suite.user_tasks[pairing[injection_id]],
                    suite.injection_tasks[injection_id],
                )
        except ValueError as exc:
            # Registry / model-name / "not injectable" failures, all pre-write.
            raise AttackPrecomputeError(str(exc)) from exc

    run_dir = Path(out_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    out_path = run_dir / "behaviour.jsonl"

    with out_path.open("w", encoding="utf-8") as fh:
        for arm in arms:
            signed_log_path = str(run_dir / f"signed_log_dojo_{arm}.log")
            for injection_id in sorted(suite.injection_tasks, key=_task_number):
                injection_task = suite.injection_tasks[injection_id]
                paired_user_task = pairing[injection_id]
                user_task = suite.user_tasks[paired_user_task]
                injections = injections_by_id.get(injection_id, {})
                for i in range(n):
                    utility, security, trace, elapsed = _run_episode(
                        suite,
                        arm,
                        user_task,
                        injection_task,
                        injections,
                        llm_factory,
                        owner_identity,
                        signed_log_path,
                        environment_factory,
                        None,  # behaviour control runs as the owner session
                        system_message,
                        model_alias,
                    )
                    record = {
                        "run_id": run_id,
                        "suite": suite.name,
                        "variant": arm,
                        "attack_id": injection_id,
                        "attack_class": "Behaviour",
                        "paired_user_task": paired_user_task,
                        "trial_index": i,
                        "utility_success": utility,
                        "final_verdict": security,
                        "tool_call_trace": trace,
                        "wall_clock_seconds": float(elapsed),
                    }
                    assert tuple(record.keys()) == BEHAVIOUR_TRIAL_KEYS
                    fh.write(json.dumps(record) + "\n")

    _write_meta(
        run_dir,
        run_id=run_id,
        suite=suite,
        arms=arms,
        n=n,
        extra={
            # Reserved keys merge LAST so a caller's extra_meta can never
            # silently shadow the run's provenance.
            **(extra_meta or {}),
            "pairing": pairing,
            "attack": attack_meta_name,
            "model_alias": model_alias,
        },
    )
    return str(out_path)
