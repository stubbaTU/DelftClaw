"""Descriptive helpers for the SQ3 report.

SQ3 is reported descriptively — we run the experiment, read a metric off each
cell, and draw a conclusion. There is no hypothesis test, no confidence
interval, and no thresholding rule (an earlier pre-registered design carried a
Wilson-CI / H0-H1 apparatus; it was dropped on supervisor feedback in favor of
plain observed rates). The only helper left here is a descriptive one.
"""

from __future__ import annotations

from typing import Iterable


def source_diversity(source_shas: Iterable[str]) -> float:
    """Fraction of runs that produced a unique generated-source SHA.

    1.0 = every compile is bit-different (no source-level reproducibility);
    1/N = all compiles produced an identical source (the strong-form result).
    Empty input returns 0.0 by convention — there's no diversity to measure.
    """
    shas = [s for s in source_shas if s]
    if not shas:
        return 0.0
    return len(set(shas)) / len(shas)
