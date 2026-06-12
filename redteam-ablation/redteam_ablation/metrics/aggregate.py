"""Aggregate a Phase A ``trials.jsonl`` grid into the paper's headline tables.

The runner emits one JSON line per trial (12 keys; see
``redteam_ablation.runner.run_ablation``). :func:`aggregate_run` reads that file
and produces three things:

1. **Per-cell ASR + Wilson bounds.** For every ``(variant, attack_id)`` cell:
   ``n``, ``successes``, ``asr = mean(final_verdict)`` and the Wilson score
   interval (:func:`redteam_ablation.metrics.wilson.wilson_interval`). Written to
   ``cell_asr.csv`` with columns
   ``variant, attack_id, attack_class, n, successes, asr, wilson_low, wilson_high``.

2. **Per-class ASR matrix.** For every ``(variant, attack_class)`` the mean
   ``final_verdict`` over *all* trials whose attack is in that class -- the
   variant x class matrix used for the cross-class robustness view.

3. **Per-variant success-class entropy.** Shannon entropy (base 2) of the
   distribution of the SUCCESSFUL trials across the five attack classes. Entropy
   ``0`` when every success is in one class (or when there are no successes);
   higher when a variant's residual successes are spread across classes -- a
   spread of failures is a worse robustness signal than a concentrated one.

Stdlib only (``csv``, ``json``, ``math``) -- no pandas/numpy.
"""

from __future__ import annotations

import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from redteam_ablation.catalogue.loader import ATTACK_CLASSES
from redteam_ablation.metrics.wilson import wilson_interval

# Stable column order for cell_asr.csv (the contracted schema).
CELL_CSV_COLUMNS = [
    "variant",
    "attack_id",
    "attack_class",
    "n",
    "successes",
    "asr",
    "wilson_low",
    "wilson_high",
]

# Canonical class order so the per-class matrix / entropy iterate deterministically.
CLASS_ORDER = sorted(ATTACK_CLASSES)


def _load_trials(trials_jsonl_path: str | Path) -> list[dict[str, Any]]:
    """Read the trials.jsonl file into a list of trial dicts."""
    path = Path(trials_jsonl_path)
    trials: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            trials.append(json.loads(line))
    return trials


def _shannon_entropy_bits(counts: list[int]) -> float:
    """Shannon entropy (base 2) of the distribution implied by ``counts``.

    Zero when the mass is concentrated in a single bucket or when total mass is
    zero (the empty-success convention). Empty / zero-count buckets contribute
    nothing.
    """
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c <= 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def aggregate_run(
    trials_jsonl_path: str | Path, out_csv_path: str | Path
) -> dict[str, Any]:
    """Aggregate ``trials_jsonl_path`` and write ``out_csv_path`` (cell_asr.csv).

    Returns a structured result::

        {
          "cells": [ {variant, attack_id, attack_class, n, successes, asr,
                      wilson_low, wilson_high}, ... ],   # one per (variant, attack)
          "class_matrix": { variant: { attack_class: asr, ... }, ... },
          "entropy": { variant: success_class_entropy_bits, ... },
        }

    and writes the per-cell table to ``out_csv_path``. The CSV is the headline
    artifact; the returned dict carries the per-class matrix and entropy the CSV
    does not encode.
    """
    trials = _load_trials(trials_jsonl_path)

    # --- per-cell accumulation: (variant, attack_id) -> stats -----------------
    # Keep insertion order of first appearance for stable CSV rows.
    cell_n: dict[tuple[str, str], int] = defaultdict(int)
    cell_succ: dict[tuple[str, str], int] = defaultdict(int)
    cell_class: dict[tuple[str, str], str] = {}
    cell_order: list[tuple[str, str]] = []

    # --- per-class accumulation: (variant, class) -> (n, successes) -----------
    class_n: dict[tuple[str, str], int] = defaultdict(int)
    class_succ: dict[tuple[str, str], int] = defaultdict(int)

    # --- per-variant success-class counts: variant -> {class -> #successes} ---
    variant_success_classes: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    variant_order: list[str] = []

    for t in trials:
        variant = t["variant"]
        attack_id = t["attack_id"]
        attack_class = t["attack_class"]
        success = bool(t["final_verdict"])

        if variant not in variant_success_classes:
            # touch to register; order tracked separately below
            pass
        if variant not in variant_order:
            variant_order.append(variant)

        cell_key = (variant, attack_id)
        if cell_key not in cell_class:
            cell_class[cell_key] = attack_class
            cell_order.append(cell_key)
        cell_n[cell_key] += 1
        if success:
            cell_succ[cell_key] += 1

        class_key = (variant, attack_class)
        class_n[class_key] += 1
        if success:
            class_succ[class_key] += 1
            variant_success_classes[variant][attack_class] += 1

    # --- build per-cell rows + Wilson bounds ----------------------------------
    cells: list[dict[str, Any]] = []
    for key in cell_order:
        variant, attack_id = key
        n = cell_n[key]
        successes = cell_succ[key]
        low, high, point = wilson_interval(successes, n)
        cells.append(
            {
                "variant": variant,
                "attack_id": attack_id,
                "attack_class": cell_class[key],
                "n": n,
                "successes": successes,
                "asr": point,
                "wilson_low": low,
                "wilson_high": high,
            }
        )

    # --- write cell_asr.csv ---------------------------------------------------
    out_path = Path(out_csv_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CELL_CSV_COLUMNS)
        writer.writeheader()
        for row in cells:
            writer.writerow(row)

    # --- per-class matrix: variant -> class -> asr ----------------------------
    class_matrix: dict[str, dict[str, float]] = {}
    for variant in variant_order:
        row: dict[str, float] = {}
        for cls in CLASS_ORDER:
            n = class_n[(variant, cls)]
            if n == 0:
                continue  # class not exercised under this variant
            row[cls] = class_succ[(variant, cls)] / n
        class_matrix[variant] = row

    # --- per-variant success-class entropy ------------------------------------
    entropy: dict[str, float] = {}
    for variant in variant_order:
        counts = [
            variant_success_classes[variant].get(cls, 0) for cls in CLASS_ORDER
        ]
        entropy[variant] = _shannon_entropy_bits(counts)

    return {
        "cells": cells,
        "class_matrix": class_matrix,
        "entropy": entropy,
    }
