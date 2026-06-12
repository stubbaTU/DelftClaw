"""Wilson score interval for the per-cell ASR confidence bounds.

``wilson_interval(successes, n, z=...)`` returns ``(low, high, point)`` where
``point`` is the raw proportion and ``(low, high)`` is the Wilson score interval.
The defining property the metrics layer relies on: the interval has NON-ZERO
width even at the boundaries ``successes == 0`` and ``successes == n`` (a naive
normal-approximation interval degenerates to zero width there), and it always
lies within ``[0, 1]``.
"""

from __future__ import annotations

import math

import pytest

from redteam_ablation.metrics.wilson import wilson_interval


# --- boundary: zero successes -----------------------------------------------


def test_zero_successes_has_positive_width_within_unit_interval():
    low, high, point = wilson_interval(0, 10)
    assert point == 0.0
    assert 0.0 <= low <= high <= 1.0
    assert high - low > 0.0  # must NOT degenerate to zero width
    assert low == 0.0 or math.isclose(low, 0.0, abs_tol=1e-12)
    # point estimate is bracketed by the interval
    assert low <= point <= high


# --- boundary: all successes ------------------------------------------------


def test_all_successes_has_positive_width_within_unit_interval():
    low, high, point = wilson_interval(10, 10)
    assert point == 1.0
    assert 0.0 <= low <= high <= 1.0
    assert high - low > 0.0
    assert math.isclose(high, 1.0, abs_tol=1e-12)
    assert low <= point <= high


# --- a known mid value sanity-checked ---------------------------------------


def test_known_midpoint_value():
    # 5/10 at the default 95% z. Reference Wilson bounds (z=1.959964):
    #   center ~ 0.5, low ~ 0.2366, high ~ 0.7634.
    low, high, point = wilson_interval(5, 10)
    assert point == 0.5
    assert math.isclose(low, 0.2365931, abs_tol=1e-4)
    assert math.isclose(high, 0.7634069, abs_tol=1e-4)
    # symmetric about 0.5 for p̂ = 0.5
    assert math.isclose((low + high) / 2.0, 0.5, abs_tol=1e-9)
    assert low <= point <= high


# --- point estimate is always bracketed -------------------------------------


@pytest.mark.parametrize("k", [0, 1, 3, 7, 10])
def test_point_estimate_bracketed(k):
    low, high, point = wilson_interval(k, 10)
    assert math.isclose(point, k / 10)
    assert low <= point <= high
    assert 0.0 <= low <= high <= 1.0


# --- n == 0 documented choice -----------------------------------------------


def test_n_zero_returns_zeros():
    assert wilson_interval(0, 0) == (0.0, 0.0, 0.0)


# --- a narrower z gives a narrower interval ---------------------------------


def test_smaller_z_narrows_interval():
    wide_low, wide_high, _ = wilson_interval(5, 10, z=1.959963984540054)
    narrow_low, narrow_high, _ = wilson_interval(5, 10, z=1.0)
    assert (narrow_high - narrow_low) < (wide_high - wide_low)
