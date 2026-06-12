"""CLI integration: ablation / phase-a alias / table subcommands, offline.

Drives the argparse entrypoint (``redteam_ablation.cli.main``) the same way the
``python -m redteam_ablation.cli ...`` invocation does, asserting it produces the
contracted artifacts (trials.jsonl, cell_asr.csv) without any network/LLM call.

Plan 2026-06-10 §1.6: the run subcommand is ``ablation`` (Phase B is cut from
the paper); ``phase-a`` survives as a working deprecated alias; the ``phase-b``
stub subcommand is REMOVED entirely.
"""

from __future__ import annotations

import csv
import json

import pytest

from redteam_ablation.cli import main
from redteam_ablation.interceptors.registry import VARIANT_ORDER
from redteam_ablation.metrics.aggregate import CELL_CSV_COLUMNS, CLASS_ORDER
from redteam_ablation.runner import TRIAL_KEYS

CATALOGUE = (
    "C:/Users/lucas/Documents/Research Project/redteam-ablation/"
    "catalogue/shapira.yaml"
)


def _read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_ablation_then_table(tmp_path, capsys):
    # Plan §1.6: `ablation` is the run subcommand (renamed from phase-a).
    out_dir = str(tmp_path)

    rc = main(
        [
            "ablation",
            "--fake",
            "--n",
            "2",
            "--run-id",
            "clitest",
            "--catalogue",
            CATALOGUE,
            "--out",
            out_dir,
        ]
    )
    assert rc == 0

    trials_path = tmp_path / "clitest" / "trials.jsonl"
    assert trials_path.exists()
    lines = _read_jsonl(trials_path)
    # 7 arms x 8 attacks x 2 trials = 112 lines, each with 12 keys (plan §1.3).
    assert len(lines) == len(VARIANT_ORDER) * 8 * 2 == 112
    for rec in lines:
        assert set(rec.keys()) == set(TRIAL_KEYS)

    # table reads trials.jsonl and writes cell_asr.csv under the same run dir.
    rc = main(["table", "--run-id", "clitest", "--out", out_dir])
    assert rc == 0

    csv_path = tmp_path / "clitest" / "cell_asr.csv"
    assert csv_path.exists()
    with csv_path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == CELL_CSV_COLUMNS
        rows = list(reader)
    # 7 arms x 8 attacks = 56 cells (plan §1.3).
    assert len(rows) == len(VARIANT_ORDER) * 8 == 56

    # table also persists the two section-5 headline quantities (Finding 2).
    matrix_path = tmp_path / "clitest" / "class_matrix.csv"
    entropy_path = tmp_path / "clitest" / "class_entropy.csv"
    assert matrix_path.exists()
    assert entropy_path.exists()

    # class_matrix.csv: one row per arm (in VARIANT_ORDER) with a "variant"
    # column followed by one column per attack class (in CLASS_ORDER).
    with matrix_path.open(encoding="utf-8", newline="") as fh:
        m_reader = csv.DictReader(fh)
        assert m_reader.fieldnames == ["variant"] + CLASS_ORDER
        m_rows = list(m_reader)
    assert [r["variant"] for r in m_rows] == list(VARIANT_ORDER)

    # class_entropy.csv: variant, entropy_bits -- one row per arm.
    with entropy_path.open(encoding="utf-8", newline="") as fh:
        e_reader = csv.DictReader(fh)
        assert e_reader.fieldnames == ["variant", "entropy_bits"]
        e_rows = list(e_reader)
    assert [r["variant"] for r in e_rows] == list(VARIANT_ORDER)
    # entropy is a non-negative float (V0: all 8 succeed across 5 classes).
    for r in e_rows:
        assert float(r["entropy_bits"]) >= 0.0


def test_phase_a_still_works_as_deprecated_alias(tmp_path):
    """Plan §1.6: `phase-a` is kept as a working deprecated alias of `ablation`
    -- it drives the same grid and writes the same artifact."""
    rc = main(
        [
            "phase-a",
            "--fake",
            "--n",
            "1",
            "--run-id",
            "alias",
            "--catalogue",
            CATALOGUE,
            "--out",
            str(tmp_path),
        ]
    )
    assert rc == 0
    trials_path = tmp_path / "alias" / "trials.jsonl"
    assert trials_path.exists()
    lines = _read_jsonl(trials_path)
    # Same 7-arm grid as `ablation`: 7 x 8 x 1 = 56 lines.
    assert len(lines) == len(VARIANT_ORDER) * 8 * 1 == 56
    for rec in lines:
        assert set(rec.keys()) == set(TRIAL_KEYS)


def test_phase_b_subcommand_is_removed():
    # Plan §1.6: the phase-b stub is removed entirely (Phase B is cut from the
    # paper) -- an unknown subcommand is an argparse error (SystemExit code 2).
    with pytest.raises(SystemExit) as excinfo:
        main(["phase-b"])
    assert excinfo.value.code == 2


@pytest.mark.parametrize("command", ["ablation", "phase-a"])
def test_run_subcommand_requires_a_runtime_flag(tmp_path, command):
    # Plan 2026-06-11 §3: --fake / --live form a REQUIRED mutually exclusive
    # group. With NEITHER flag, argparse refuses with a usage error (code 2)
    # rather than running. Applies to the new name and the deprecated alias.
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                command,
                "--n",
                "1",
                "--run-id",
                "noflag",
                "--out",
                str(tmp_path),
            ]
        )
    assert excinfo.value.code == 2


@pytest.mark.parametrize("command", ["ablation", "phase-a"])
def test_run_subcommand_rejects_both_fake_and_live(tmp_path, command):
    # Plan §3: --fake and --live are mutually exclusive -- passing BOTH is an
    # argparse usage error (code 2), never a silent precedence.
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                command,
                "--fake",
                "--live",
                "--n",
                "1",
                "--run-id",
                "both",
                "--out",
                str(tmp_path),
            ]
        )
    assert excinfo.value.code == 2
