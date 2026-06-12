"""Substrate-2 behaviour-control runner -> behaviour.jsonl (plan §2.3, F9).

Each suite injection task is ONE attack in the Behaviour control column
(attack_class="Behaviour"); it executes against a pre-registered paired user
task (default rule: the lowest-numbered user task; recorded in every record as
``paired_user_task``). ``final_verdict`` is the suite's own ``security``
verdict (True = the injected goal was achieved), so the records aggregate
through the existing ``metrics.aggregate.aggregate_run`` unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redteam_ablation.metrics.aggregate import aggregate_run
from redteam_ablation.runtime.fake import make_owner_identity
from redteam_ablation.substrates.agentdojo_native.runner import (
    default_pairing,
    run_behaviour_control,
)

from tests.agentdojo_stub import FakeLLM, StubEnv, make_stub_suite, tool_call

OWNER = make_owner_identity()


def _hijacked_llm_factory():
    """Scripted agent that FOLLOWS the injected goal: wipes the notes."""
    return FakeLLM([[tool_call("delete_notes")], "done as instructed"])


def _faithful_llm_factory():
    """Scripted agent that ignores the injection and just solves the task."""
    return FakeLLM([[tool_call("read_notes")], "your notes say: alpha"])


def _run(tmp_path, llm_factory, arms=("V0",), n=1):
    out = run_behaviour_control(
        suite=make_stub_suite(),
        arms=list(arms),
        n=n,
        llm_factory=llm_factory,
        run_id="dojo-control",
        out_dir=tmp_path,
        owner_identity=OWNER,
        environment_factory=StubEnv,
    )
    lines = Path(out).read_text(encoding="utf-8").splitlines()
    return out, [json.loads(line) for line in lines if line.strip()]


def test_default_pairing_is_lowest_numbered_user_task():
    suite = make_stub_suite()
    pairing = default_pairing(suite)
    assert pairing == {"injection_task_0": "user_task_0"}


def test_writes_behaviour_jsonl_with_grid_shape(tmp_path):
    out, records = _run(tmp_path, _hijacked_llm_factory, arms=("V0", "P1-strict"), n=2)
    assert Path(out) == tmp_path / "dojo-control" / "behaviour.jsonl"
    # 1 injection task x 2 arms x 2 trials.
    assert len(records) == 4
    assert {r["variant"] for r in records} == {"V0", "P1-strict"}
    assert {r["trial_index"] for r in records} == {0, 1}


def test_records_pin_attack_identity_and_pairing(tmp_path):
    _, records = _run(tmp_path, _hijacked_llm_factory)
    for rec in records:
        assert rec["attack_id"] == "injection_task_0"
        assert rec["attack_class"] == "Behaviour"
        assert rec["paired_user_task"] == "user_task_0"
        assert rec["suite"] == "stub-notes"


def test_final_verdict_is_the_security_outcome(tmp_path):
    """Hijacked agent -> the injected goal lands -> final_verdict True;
    faithful agent -> goal not achieved -> final_verdict False. The verdict is
    the benchmark's own deterministic security() on the post-environment."""
    _, hijacked = _run(tmp_path, _hijacked_llm_factory)
    assert all(r["final_verdict"] is True for r in hijacked)

    _, faithful = _run(tmp_path, _faithful_llm_factory)
    assert all(r["final_verdict"] is False for r in faithful)


def test_records_aggregate_through_existing_table(tmp_path):
    """The behaviour records feed metrics.aggregate.aggregate_run unchanged:
    a (variant x attack) cell table with Wilson bounds comes out."""
    out, _ = _run(tmp_path, _hijacked_llm_factory, arms=("V0",), n=2)
    result = aggregate_run(out, tmp_path / "cell.csv")
    (cell,) = result["cells"]
    assert cell["variant"] == "V0"
    assert cell["attack_id"] == "injection_task_0"
    assert cell["attack_class"] == "Behaviour"
    assert cell["n"] == 2
    assert cell["asr"] == 1.0


def test_orthogonality_integrity_arms_do_not_move_behaviour(tmp_path):
    """The control prediction: integrity arms (strict included) do NOT stop a
    Behaviour-class hijack -- the session is the owner's, the constitution
    matches, so P1/P3 pass and the injected call executes (ASR == V0)."""
    _, records = _run(
        tmp_path, _hijacked_llm_factory, arms=("V0", "P1-strict", "P3-strict")
    )
    by_arm = {r["variant"]: r for r in records}
    assert by_arm["V0"]["final_verdict"] is True
    assert by_arm["P1-strict"]["final_verdict"] is True
    assert by_arm["P3-strict"]["final_verdict"] is True


# ---------------------------------------------------------------------------
# Attack loader seam (plan 2026-06-11 attack wiring, design pins 2-7)
#
# The runner loads ONE attack per run (via the injectable attack_loader seam),
# precomputes each injection task's injections BEFORE the run dir/file exist,
# and threads a model alias into the load-target + episode pipeline names.
# Tests go exclusively through the fake loader: the real BaseAttack.__init__
# reads injection_vectors.yaml off disk, which the offline stub suite lacks.
# ---------------------------------------------------------------------------


class _FakeAttack:
    """Stand-in for an agentdojo BaseAttack, handed back by the loader seam.

    Records every ``.attack`` call; can be told to raise a ValueError (the
    'not injectable' case) so the fail-before-write contract is exercisable
    without ever constructing a real attack against the stub suite.
    """

    def __init__(self, name="x", *, raises=False):
        self.name = name
        self._raises = raises
        self.attack_calls = []

    def attack(self, user_task, injection_task):
        self.attack_calls.append((user_task, injection_task))
        if self._raises:
            raise ValueError("user_task is not injectable.")
        return {"injection_payload": "EVIL"}


def _make_recording_loader(attack_obj):
    """A fake ``load_attack(attack_name, task_suite, target_pipeline)`` that
    records its args (incl. the target pipeline's ``.name``) and returns the
    given fake attack. Mirrors the real attack_registry.load_attack signature.
    """
    calls = []

    def loader(attack_name, task_suite, target_pipeline):
        calls.append(
            {
                "attack_name": attack_name,
                "suite": task_suite,
                "target": target_pipeline,
                "target_name": getattr(target_pipeline, "name", None),
            }
        )
        return attack_obj

    return loader, calls


def test_attack_loader_seam_threads_target_and_injections(tmp_path):
    """The loader is called EXACTLY once -- with the attack name, the suite
    object, and a minimal load-target pipeline named
    ``redteam-ablation/{first-arm}/{alias}`` -- and the loaded attack's
    ``.attack`` runs once per injection task (design pins 2-3)."""
    suite = make_stub_suite()
    n_injection_tasks = len(suite.injection_tasks)
    attack = _FakeAttack(name="x")
    loader, calls = _make_recording_loader(attack)

    run_behaviour_control(
        suite=suite,
        arms=["V0"],
        n=1,
        llm_factory=_hijacked_llm_factory,
        run_id="seam",
        out_dir=tmp_path,
        owner_identity=OWNER,
        environment_factory=StubEnv,
        attack_name="x",
        model_alias="claude-3-7-sonnet-20250219",
        attack_loader=loader,
    )

    assert len(calls) == 1
    call = calls[0]
    assert call["attack_name"] == "x"
    assert call["suite"] is suite
    assert call["target_name"] == "redteam-ablation/V0/claude-3-7-sonnet-20250219"
    # One .attack() per injection task (here the stub's single injection task).
    assert len(attack.attack_calls) == n_injection_tasks


def test_precomputed_injections_reach_every_episode(tmp_path, monkeypatch):
    """The wire this change exists to connect, pinned end-to-end: the
    precomputed injections are the ``injections`` argument of EVERY episode's
    ``run_task_with_pipeline`` call (a key mismatch in the runner's
    ``injections_by_id`` lookup would silently re-open gap A7), the alias
    rides in every arm's episode pipeline name, the loader fires once per RUN
    (not per arm), and the attack sees exactly the PAIRED user task."""
    suite = make_stub_suite()
    attack = _FakeAttack(name="x")
    loader, calls = _make_recording_loader(attack)
    real_run = suite.run_task_with_pipeline
    episodes = []

    def recording_run(pipeline, user_task, injection_task, injections, **kwargs):
        episodes.append({"name": pipeline.name, "injections": dict(injections)})
        return real_run(pipeline, user_task, injection_task, injections, **kwargs)

    monkeypatch.setattr(suite, "run_task_with_pipeline", recording_run)

    run_behaviour_control(
        suite=suite,
        arms=["V0", "P1-strict"],
        n=2,
        llm_factory=_hijacked_llm_factory,
        run_id="thread",
        out_dir=tmp_path,
        owner_identity=OWNER,
        environment_factory=StubEnv,
        attack_name="x",
        model_alias="claude-3-7-sonnet-20250219",
        attack_loader=loader,
    )

    # 2 arms x 1 injection task x 2 trials, every one fed the precomputed dict.
    assert len(episodes) == 4
    assert all(e["injections"] == {"injection_payload": "EVIL"} for e in episodes)
    # The alias is in EVERY arm's episode pipeline name -- the name the attack
    # resolved against matches the names the episodes actually run under.
    assert {e["name"] for e in episodes} == {
        "redteam-ablation/V0/claude-3-7-sonnet-20250219",
        "redteam-ablation/P1-strict/claude-3-7-sonnet-20250219",
    }
    # Load-once per RUN: two arms, still exactly one loader call and one
    # .attack() per injection task (injections are arm-invariant).
    assert len(calls) == 1
    assert attack.attack_calls == [
        (suite.user_tasks["user_task_0"], suite.injection_tasks["injection_task_0"])
    ]


def test_offline_mode_preserved_meta_attack_is_none(tmp_path, monkeypatch):
    """With attack_name=None (default) the run stays in offline/scripted mode:
    meta.json records ``attack: None, model_alias: None`` and the episode
    pipeline names carry NO alias suffix -- the byte-identical legacy path."""
    suite = make_stub_suite()
    real_run = suite.run_task_with_pipeline
    names = []

    def recording_run(pipeline, *args, **kwargs):
        names.append(pipeline.name)
        return real_run(pipeline, *args, **kwargs)

    monkeypatch.setattr(suite, "run_task_with_pipeline", recording_run)

    out = run_behaviour_control(
        suite=suite,
        arms=["V0"],
        n=1,
        llm_factory=_hijacked_llm_factory,
        run_id="dojo-control",
        out_dir=tmp_path,
        owner_identity=OWNER,
        environment_factory=StubEnv,
    )
    records = [
        json.loads(line)
        for line in Path(out).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(records) == 1  # 1 arm x 1 injection task x 1 trial, unchanged
    assert names == ["redteam-ablation/V0"]
    meta = json.loads((Path(out).parent / "meta.json").read_text(encoding="utf-8"))
    assert meta["attack"] is None
    assert meta["model_alias"] is None


def test_attack_name_requires_model_alias(tmp_path):
    """attack_name without model_alias is refused up front (the stock attacks
    resolve the model's prose name from the load-target pipeline name, so a
    missing alias would surface as a confusing agentdojo error mid-load)."""
    with pytest.raises(ValueError, match="model_alias"):
        run_behaviour_control(
            suite=make_stub_suite(),
            arms=["V0"],
            n=1,
            llm_factory=_hijacked_llm_factory,
            run_id="noalias",
            out_dir=tmp_path,
            owner_identity=OWNER,
            environment_factory=StubEnv,
            attack_name="x",
        )
    assert list(tmp_path.iterdir()) == []


def test_meta_attack_falls_back_to_requested_name(tmp_path):
    """A loader returning an attack object WITHOUT a ``.name`` attribute still
    pins provenance: meta.json falls back to the requested attack_name."""

    class _NamelessAttack:
        def attack(self, user_task, injection_task):
            return {"injection_payload": "EVIL"}

    loader, _ = _make_recording_loader(_NamelessAttack())
    out = run_behaviour_control(
        suite=make_stub_suite(),
        arms=["V0"],
        n=1,
        llm_factory=_hijacked_llm_factory,
        run_id="nameless",
        out_dir=tmp_path,
        owner_identity=OWNER,
        environment_factory=StubEnv,
        attack_name="x",
        model_alias="claude-3-7-sonnet-20250219",
        attack_loader=loader,
    )
    meta = json.loads((Path(out).parent / "meta.json").read_text(encoding="utf-8"))
    assert meta["attack"] == "x"


def test_loader_failure_fails_before_any_write(tmp_path):
    """A ValueError raised while precomputing injections (here ``.attack``
    raises, the 'not injectable' case) propagates and NOTHING is written: the
    run dir for that run_id is never even created (design pin 2: fail before
    mkdir/open)."""
    suite = make_stub_suite()
    attack = _FakeAttack(name="x", raises=True)
    loader, _ = _make_recording_loader(attack)

    with pytest.raises(ValueError):
        run_behaviour_control(
            suite=suite,
            arms=["V0"],
            n=1,
            llm_factory=_hijacked_llm_factory,
            run_id="boom",
            out_dir=tmp_path,
            owner_identity=OWNER,
            environment_factory=StubEnv,
            attack_name="x",
            model_alias="claude-3-7-sonnet-20250219",
            attack_loader=loader,
        )

    assert not (tmp_path / "boom").exists()
    assert list(tmp_path.iterdir()) == []


def test_meta_records_attack_name_and_model_alias(tmp_path):
    """meta.json pins the LOADED attack's ``.name`` and the model alias passed
    through (design pin 7)."""
    suite = make_stub_suite()
    attack = _FakeAttack(name="x")
    loader, _ = _make_recording_loader(attack)

    out = run_behaviour_control(
        suite=suite,
        arms=["V0"],
        n=1,
        llm_factory=_hijacked_llm_factory,
        run_id="meta",
        out_dir=tmp_path,
        owner_identity=OWNER,
        environment_factory=StubEnv,
        attack_name="x",
        model_alias="claude-3-7-sonnet-20250219",
        attack_loader=loader,
    )

    meta = json.loads((Path(out).parent / "meta.json").read_text(encoding="utf-8"))
    assert meta["attack"] == "x"
    assert meta["model_alias"] == "claude-3-7-sonnet-20250219"
