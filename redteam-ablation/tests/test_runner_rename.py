"""Runner rename: ``run_ablation`` with ``run_phase_a`` kept as alias (plan §1.6).

Phase B is cut from the paper, so the runner's driver loses its phase name:
``run_phase_a`` is renamed to ``run_ablation`` and a module-level alias
``run_phase_a = run_ablation`` is retained so old imports / tests keep working.
"""

from __future__ import annotations

import json

from redteam_ablation.runner import run_ablation, run_phase_a
from redteam_ablation.runtime.fake import FakeRuntime

CATALOGUE = (
    "C:/Users/lucas/Documents/Research Project/redteam-ablation/"
    "catalogue/shapira.yaml"
)


def test_run_phase_a_is_a_module_level_alias_of_run_ablation():
    assert run_phase_a is run_ablation


def test_run_ablation_drives_the_grid(tmp_path):
    """The renamed callable is the same driver: it writes trials.jsonl."""
    out_path = run_ablation(
        catalogue_path=CATALOGUE,
        variants=["V0"],
        n=1,
        runtime=FakeRuntime(),
        run_id="rename-smoke",
        out_dir=str(tmp_path),
    )
    assert out_path.endswith("trials.jsonl")
    with open(out_path, encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh if line.strip()]
    # 1 variant x 8 attacks x 1 trial.
    assert len(lines) == 8
