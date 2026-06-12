"""Phase A runner: drive the grid and emit the 12-key trials.jsonl.

``run_phase_a(catalogue_path, variants, n, runtime, run_id, out_dir, ...)``
iterates (variant x attack x trial-index), runs each episode through a
``Dispatcher(make_fake_policies(), interceptors_for(variant))``, judges it, times
it, and appends one JSON line per trial with EXACTLY the 12 contracted keys to
``<out_dir>/<run_id>/trials.jsonl``. With the deterministic ``FakeRuntime`` over
the real 8-attack catalogue this is fully offline and reproducible.
"""

from __future__ import annotations

import json

import pytest

from redteam_ablation.runner import run_phase_a
from redteam_ablation.runtime.fake import FakeRuntime

CATALOGUE = (
    "C:/Users/lucas/Documents/Research Project/redteam-ablation/"
    "catalogue/shapira.yaml"
)

EXPECTED_KEYS = {
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
}


def _read_lines(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_run_phase_a_writes_8x2_lines(tmp_path):
    out_path = run_phase_a(
        catalogue_path=CATALOGUE,
        variants=["V0"],
        n=2,
        runtime=FakeRuntime(),
        run_id="smoke",
        out_dir=str(tmp_path),
    )

    # returns the path to trials.jsonl under <out_dir>/<run_id>/
    assert out_path.endswith("trials.jsonl")
    lines = _read_lines(out_path)
    # 8 attacks x 2 trials x 1 variant = 16 lines
    assert len(lines) == 16


def test_every_line_has_exactly_12_keys_with_types(tmp_path):
    out_path = run_phase_a(
        catalogue_path=CATALOGUE,
        variants=["V0"],
        n=2,
        runtime=FakeRuntime(),
        run_id="smoke",
        out_dir=str(tmp_path),
    )
    lines = _read_lines(out_path)

    for rec in lines:
        assert set(rec.keys()) == EXPECTED_KEYS
        assert isinstance(rec["run_id"], str)
        assert isinstance(rec["catalogue_commit"], str)
        assert rec["variant"] == "V0"
        assert isinstance(rec["attack_id"], str)
        assert isinstance(rec["attack_class"], str)
        assert isinstance(rec["trial_index"], int)
        assert isinstance(rec["seed"], int)
        assert isinstance(rec["tool_call_trace"], list)
        assert isinstance(rec["final_verdict"], bool)
        assert isinstance(rec["deterministic_verdict"], bool)
        # judge_verdict is None on the deterministic path
        assert rec["judge_verdict"] is None
        assert isinstance(rec["wall_clock_seconds"], float)


def test_v0_all_successes_and_seeds_distinct(tmp_path):
    out_path = run_phase_a(
        catalogue_path=CATALOGUE,
        variants=["V0"],
        n=2,
        runtime=FakeRuntime(),
        run_id="smoke",
        out_dir=str(tmp_path),
    )
    lines = _read_lines(out_path)

    # V0 has no interceptors: every dangerous tool fires -> all successes.
    assert all(rec["final_verdict"] is True for rec in lines)

    # trial indices cover range(2) for each attack
    trial_indices = sorted({rec["trial_index"] for rec in lines})
    assert trial_indices == [0, 1]

    # seeds are distinct per (attack, trial)
    seeds = [rec["seed"] for rec in lines]
    assert len(seeds) == len(set(seeds))

    # exactly the 8 framework attacks appear
    attack_ids = {rec["attack_id"] for rec in lines}
    assert attack_ids == {
        "SH-01",
        "SH-02",
        "SH-03",
        "SH-04",
        "SH-05",
        "SH-06",
        "SH-07",
        "SH-10",
    }


def test_run_phase_a_is_deterministic(tmp_path):
    a = run_phase_a(
        catalogue_path=CATALOGUE,
        variants=["V0"],
        n=2,
        runtime=FakeRuntime(),
        run_id="runA",
        out_dir=str(tmp_path),
    )
    b = run_phase_a(
        catalogue_path=CATALOGUE,
        variants=["V0"],
        n=2,
        runtime=FakeRuntime(),
        run_id="runB",
        out_dir=str(tmp_path),
    )
    la = _read_lines(a)
    lb = _read_lines(b)

    # Same seeds, verdicts, AND tool-call traces for the same (variant, attack,
    # trial), regardless of run_id (run_id is not part of the seed). Including
    # the serialized trace + deterministic_verdict in the compared value catches
    # any nondeterminism in the dispatched episode, not just the seed (Finding 6).
    def key(rec):
        return (rec["variant"], rec["attack_id"], rec["trial_index"])

    def value(rec):
        return (
            rec["seed"],
            rec["final_verdict"],
            rec["deterministic_verdict"],
            json.dumps(rec["tool_call_trace"], sort_keys=True),
        )

    da = {key(r): value(r) for r in la}
    db = {key(r): value(r) for r in lb}
    assert da == db

    # Stronger still: the two trials.jsonl files are byte-identical after
    # stripping the only fields allowed to differ (run_id, wall_clock_seconds).
    def canonical(records):
        canon = []
        for r in records:
            r = dict(r)
            r.pop("run_id")
            r.pop("wall_clock_seconds")
            canon.append(json.dumps(r, sort_keys=True))
        return canon

    assert canonical(la) == canonical(lb)


def test_run_phase_a_unknown_variant_raises(tmp_path):
    """An unknown variant fails loudly: the runner propagates interceptors_for's
    KeyError rather than silently running an empty defence set (Finding 9)."""
    with pytest.raises(KeyError):
        run_phase_a(
            catalogue_path=CATALOGUE,
            variants=["V0", "V9-nope"],
            n=1,
            runtime=FakeRuntime(),
            run_id="badvariant",
            out_dir=str(tmp_path),
        )
