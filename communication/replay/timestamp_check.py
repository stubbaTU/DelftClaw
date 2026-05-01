"""Wall-clock skew window check for ``WireFrame.timestamp_ms``."""

from __future__ import annotations

import time


def is_within_skew(timestamp_ms: int, max_skew_ms: int = 120_000, *, now_ms: int | None = None) -> bool:
    """True iff ``timestamp_ms`` is within ``max_skew_ms`` of the local clock.

    ``now_ms`` is a hook for deterministic testing.
    """
    current = int(time.time() * 1000) if now_ms is None else now_ms
    return abs(current - timestamp_ms) <= max_skew_ms
