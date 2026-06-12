"""Wilson score confidence interval for a binomial proportion.

The per-cell ASR (attack-success rate) is a binomial proportion ``k / n`` over a
small number of trials. The normal-approximation ("Wald") interval is unusable
here: at the boundaries ``k == 0`` and ``k == n`` it collapses to zero width,
falsely implying perfect certainty exactly where the small-sample uncertainty is
largest. The **Wilson score interval** keeps a sensible, non-zero width at the
boundaries and stays inside ``[0, 1]``, so it is what the metrics layer reports.

:func:`wilson_interval` returns ``(low, high, point)`` where ``point = k / n`` is
the raw proportion (the plotted ASR) and ``(low, high)`` is the Wilson interval
at the given ``z`` (default ``z`` is the two-sided 95% normal quantile). Stdlib
``math`` only -- no numpy/scipy.
"""

from __future__ import annotations

import math

# Two-sided 95% quantile of the standard normal (``scipy.stats.norm.ppf(0.975)``),
# pinned as a literal so the module has no scipy dependency.
Z_95 = 1.959963984540054


def wilson_interval(
    successes: int, n: int, z: float = Z_95
) -> tuple[float, float, float]:
    """Return ``(low, high, point)`` -- the Wilson score interval and proportion.

    ``successes`` is the count of attack successes in ``n`` trials. ``point`` is
    the raw proportion ``successes / n`` (the reported ASR). ``low``/``high`` are
    the Wilson score bounds at confidence quantile ``z``, clamped to ``[0, 1]``.

    The interval has NON-ZERO width even at ``successes == 0`` and
    ``successes == n`` (unlike the normal-approximation interval), which is the
    whole reason the harness uses Wilson rather than Wald.

    ``n == 0`` is the empty-cell convention: there is no proportion and no
    interval, so ``(0.0, 0.0, 0.0)`` is returned.
    """
    if n < 0:
        raise ValueError(f"n must be non-negative, got {n}")
    if successes < 0 or successes > n:
        raise ValueError(
            f"successes must be in [0, n]; got successes={successes}, n={n}"
        )
    if n == 0:
        # Empty cell: no proportion, no interval. Documented degenerate case.
        return (0.0, 0.0, 0.0)

    point = successes / n

    # Wilson score interval.
    #   denom   = 1 + z^2/n
    #   center  = (p_hat + z^2/(2n)) / denom
    #   margin  = (z / denom) * sqrt( p_hat*(1-p_hat)/n + z^2/(4 n^2) )
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (point + z2 / (2.0 * n)) / denom
    margin = (z / denom) * math.sqrt(
        point * (1.0 - point) / n + z2 / (4.0 * n * n)
    )

    low = center - margin
    high = center + margin

    # Clamp into the unit interval (rounding can push a boundary a hair outside).
    low = min(1.0, max(0.0, low))
    high = min(1.0, max(0.0, high))

    # At the count boundaries the Wilson bound is exactly 0 (k==0) / 1 (k==n);
    # pin them so floating-point error can never leave ``point`` unbracketed
    # (e.g. high == 0.999... while point == 1.0).
    if successes == 0:
        low = 0.0
    if successes == n:
        high = 1.0
    return (low, high, point)
