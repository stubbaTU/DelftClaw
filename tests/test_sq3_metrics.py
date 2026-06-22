"""Tests for ``sq3.metrics`` — the descriptive source-diversity helper.

The Wilson-CI / H0-H1 decision machinery this module used to carry was removed
when SQ3 moved to a descriptive design; ``source_diversity`` is all that's left.
"""

from __future__ import annotations

from experiments.metrics import source_diversity


def test_source_diversity_all_unique():
    assert source_diversity(["a", "b", "c", "d"]) == 1.0


def test_source_diversity_all_identical():
    assert source_diversity(["x"] * 20) == 1 / 20


def test_source_diversity_empty_returns_zero_by_convention():
    """Empty input has no diversity to measure; return 0.0 rather than
    NaN so the report column is always a clean float."""
    assert source_diversity([]) == 0.0


def test_source_diversity_drops_empty_strings():
    """An empty SHA (means: missing) should not count as a 'unique' source."""
    assert source_diversity(["x", "", "x"]) == 1 / 2
