"""End-to-end offline smoke: run_phase_a -> aggregate_run over the full grid.

This is the integration test that proves the whole offline pipeline composes:
the runner drives the full (VARIANT_ORDER x 8 attacks x n) grid through the
deterministic :class:`FakeRuntime`, writes a 12-key ``trials.jsonl``, and the
aggregator turns it into a well-formed ``cell_asr.csv``. Everything is offline,
deterministic, and touches no network/LLM.

Grid sizing (n=2): 7 arms x 8 attacks x 2 trials = 112 trial lines, and one
cell per (arm, attack) = 7 x 8 = 56 cell rows in the CSV (plan 2026-06-10
§1.3/§1.4: the grid is the 7-arm enforcement ladder).
"""

from __future__ import annotations

import csv
import json

from redteam_ablation.interceptors.registry import VARIANT_ORDER
from redteam_ablation.metrics.aggregate import CELL_CSV_COLUMNS, aggregate_run
from redteam_ablation.runner import TRIAL_KEYS, run_phase_a
from redteam_ablation.runtime.fake import FakeRuntime

CATALOGUE = (
    "C:/Users/lucas/Documents/Research Project/redteam-ablation/"
    "catalogue/shapira.yaml"
)

N = 2
N_VARIANTS = 7  # plan §1.3: VARIANT_ORDER is the 7-arm ladder (was 5 variants)
N_ATTACKS = 8


def _read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_end_to_end_fake_grid(tmp_path):
    # --- run the full grid through the fake runtime ---------------------------
    trials_path = run_phase_a(
        catalogue_path=CATALOGUE,
        variants=VARIANT_ORDER,
        n=N,
        runtime=FakeRuntime(),
        run_id="e2e",
        out_dir=str(tmp_path),
    )
    assert trials_path.endswith("trials.jsonl")

    lines = _read_jsonl(trials_path)
    # 7 arms x 8 attacks x 2 trials = 112 trial lines (plan §1.3/§1.4).
    assert len(lines) == N_VARIANTS * N_ATTACKS * N == 112

    # Every line carries EXACTLY the 12 contracted keys.
    expected_keys = set(TRIAL_KEYS)
    assert len(expected_keys) == 12
    for rec in lines:
        assert set(rec.keys()) == expected_keys

    # Every variant in VARIANT_ORDER is represented, each with 8*2 = 16 lines.
    variants_seen = {rec["variant"] for rec in lines}
    assert variants_seen == set(VARIANT_ORDER)
    for variant in VARIANT_ORDER:
        assert sum(1 for rec in lines if rec["variant"] == variant) == 16

    # --- aggregate into a well-formed cell_asr.csv ----------------------------
    out_csv = tmp_path / "e2e" / "cell_asr.csv"
    result = aggregate_run(trials_path, str(out_csv))
    assert out_csv.exists()

    with out_csv.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == CELL_CSV_COLUMNS
        rows = list(reader)

    # One cell per (arm, attack) = 7 x 8 = 56 rows (header excluded by reader;
    # plan §1.3/§1.4).
    assert len(rows) == N_VARIANTS * N_ATTACKS == 56

    # Wilson columns are numeric and well-bracketed; asr equals successes / n.
    for row in rows:
        n = int(row["n"])
        successes = int(row["successes"])
        asr = float(row["asr"])
        low = float(row["wilson_low"])
        high = float(row["wilson_high"])
        assert n == N
        assert 0 <= successes <= n
        assert 0.0 <= low <= asr <= high <= 1.0
        assert abs(asr - successes / n) < 1e-9
        assert row["variant"] in VARIANT_ORDER

    # The aggregator's structured return also covers all variants.
    assert set(result["cells"][0].keys()) == set(CELL_CSV_COLUMNS)
    assert set(result["entropy"].keys()) == set(VARIANT_ORDER)
