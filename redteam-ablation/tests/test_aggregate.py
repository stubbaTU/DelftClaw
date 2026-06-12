"""Aggregation of a trials.jsonl grid into per-cell / per-class / entropy stats.

``aggregate_run(trials_jsonl_path, out_csv_path)`` reads the 12-key trial lines
the runner writes, then:

* computes per-(variant, attack_id) ASR (mean ``final_verdict``) + Wilson bounds
  and writes ``cell_asr.csv`` with the contracted columns;
* builds a per-class (variant x attack_class) ASR matrix;
* computes per-variant Shannon entropy (base 2) of the distribution of the
  SUCCESSFUL trials over the five attack classes (0 when all successes share one
  class; > 0 when spread; 0 when there are no successes).

These tests hand-write a tiny synthetic grid so the expected numbers are known.
"""

from __future__ import annotations

import csv
import json
import math

from redteam_ablation.metrics.aggregate import aggregate_run


def _trial(variant, attack_id, attack_class, idx, final):
    """One synthetic 12-key trial line dict."""
    return {
        "run_id": "synthetic",
        "catalogue_commit": "deadbeef",
        "variant": variant,
        "attack_id": attack_id,
        "attack_class": attack_class,
        "trial_index": idx,
        "seed": 1000 + idx,
        "tool_call_trace": [{"proposed_tool": "x"}],
        "judge_verdict": None,
        "deterministic_verdict": final,
        "final_verdict": final,
        "wall_clock_seconds": 0.001,
    }


def _write_jsonl(path, trials):
    with open(path, "w", encoding="utf-8") as fh:
        for t in trials:
            fh.write(json.dumps(t) + "\n")


def _read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_per_cell_asr_and_wilson_columns(tmp_path):
    trials = [
        # V0 / SH-01 (Behaviour): 4 trials, 3 successes -> ASR 0.75
        _trial("V0", "SH-01", "Behaviour", 0, True),
        _trial("V0", "SH-01", "Behaviour", 1, True),
        _trial("V0", "SH-01", "Behaviour", 2, True),
        _trial("V0", "SH-01", "Behaviour", 3, False),
        # V0 / SH-07 (Audit-trail): 2 trials, 0 successes -> ASR 0.0
        _trial("V0", "SH-07", "Audit-trail", 0, False),
        _trial("V0", "SH-07", "Audit-trail", 1, False),
    ]
    jsonl = tmp_path / "trials.jsonl"
    out = tmp_path / "cell_asr.csv"
    _write_jsonl(jsonl, trials)

    aggregate_run(str(jsonl), str(out))

    rows = _read_csv(out)
    expected_cols = {
        "variant",
        "attack_id",
        "attack_class",
        "n",
        "successes",
        "asr",
        "wilson_low",
        "wilson_high",
    }
    assert rows, "cell_asr.csv must have at least one data row"
    assert expected_cols.issubset(set(rows[0].keys()))

    by_key = {(r["variant"], r["attack_id"]): r for r in rows}

    sh01 = by_key[("V0", "SH-01")]
    assert int(sh01["n"]) == 4
    assert int(sh01["successes"]) == 3
    assert math.isclose(float(sh01["asr"]), 0.75)
    assert sh01["attack_class"] == "Behaviour"  # class carried through
    lo, hi = float(sh01["wilson_low"]), float(sh01["wilson_high"])
    assert 0.0 <= lo <= 0.75 <= hi <= 1.0
    assert hi - lo > 0.0

    sh07 = by_key[("V0", "SH-07")]
    assert int(sh07["n"]) == 2
    assert int(sh07["successes"]) == 0
    assert math.isclose(float(sh07["asr"]), 0.0)
    lo7, hi7 = float(sh07["wilson_low"]), float(sh07["wilson_high"])
    # boundary cell still has non-zero width
    assert hi7 - lo7 > 0.0
    assert 0.0 <= lo7 <= hi7 <= 1.0


def test_per_class_matrix_present(tmp_path):
    trials = [
        _trial("V0", "SH-01", "Behaviour", 0, True),
        _trial("V0", "SH-02", "Behaviour", 0, False),
        _trial("V0", "SH-07", "Audit-trail", 0, True),
    ]
    jsonl = tmp_path / "trials.jsonl"
    out = tmp_path / "cell_asr.csv"
    _write_jsonl(jsonl, trials)

    result = aggregate_run(str(jsonl), str(out))

    # aggregate_run returns a structured result carrying the per-class matrix.
    assert result is not None
    matrix = result["class_matrix"]
    # Behaviour: 1 of 2 -> 0.5 ; Audit-trail: 1 of 1 -> 1.0
    assert math.isclose(matrix["V0"]["Behaviour"], 0.5)
    assert math.isclose(matrix["V0"]["Audit-trail"], 1.0)


def test_entropy_zero_when_all_successes_one_class(tmp_path):
    # Every success is a Behaviour attack -> entropy 0.
    trials = [
        _trial("V0", "SH-01", "Behaviour", 0, True),
        _trial("V0", "SH-02", "Behaviour", 0, True),
        _trial("V0", "SH-07", "Audit-trail", 0, False),  # not a success
    ]
    jsonl = tmp_path / "trials.jsonl"
    out = tmp_path / "cell_asr.csv"
    _write_jsonl(jsonl, trials)

    result = aggregate_run(str(jsonl), str(out))
    assert math.isclose(result["entropy"]["V0"], 0.0)


def test_entropy_positive_when_successes_spread_across_classes(tmp_path):
    # Successes split evenly across two classes -> entropy = 1 bit.
    trials = [
        _trial("V0", "SH-01", "Behaviour", 0, True),
        _trial("V0", "SH-07", "Audit-trail", 0, True),
    ]
    jsonl = tmp_path / "trials.jsonl"
    out = tmp_path / "cell_asr.csv"
    _write_jsonl(jsonl, trials)

    result = aggregate_run(str(jsonl), str(out))
    assert math.isclose(result["entropy"]["V0"], 1.0, abs_tol=1e-9)


def test_entropy_zero_when_no_successes(tmp_path):
    trials = [
        _trial("V0", "SH-01", "Behaviour", 0, False),
        _trial("V0", "SH-07", "Audit-trail", 0, False),
    ]
    jsonl = tmp_path / "trials.jsonl"
    out = tmp_path / "cell_asr.csv"
    _write_jsonl(jsonl, trials)

    result = aggregate_run(str(jsonl), str(out))
    assert math.isclose(result["entropy"]["V0"], 0.0)


def test_aggregate_skips_blank_lines(tmp_path):
    """Blank / whitespace-only lines in trials.jsonl are ignored, not parsed.

    A stray blank line (e.g. a trailing newline or an editor artifact) must not
    crash the aggregator or count as a trial (Finding 9).
    """
    trials = [
        _trial("V0", "SH-01", "Behaviour", 0, True),
        _trial("V0", "SH-01", "Behaviour", 1, False),
    ]
    jsonl = tmp_path / "trials.jsonl"
    out = tmp_path / "cell_asr.csv"
    # Interleave blank / whitespace-only lines among the real JSON lines.
    with open(jsonl, "w", encoding="utf-8") as fh:
        fh.write("\n")  # leading blank
        fh.write(json.dumps(trials[0]) + "\n")
        fh.write("   \n")  # whitespace-only
        fh.write("\n")
        fh.write(json.dumps(trials[1]) + "\n")
        fh.write("\n")  # trailing blank

    result = aggregate_run(str(jsonl), str(out))

    # Exactly 2 trials counted for the one cell -- blanks contributed nothing.
    cells = result["cells"]
    assert len(cells) == 1
    assert cells[0]["n"] == 2
    assert cells[0]["successes"] == 1
    rows = _read_csv(out)
    assert len(rows) == 1
    assert int(rows[0]["n"]) == 2
