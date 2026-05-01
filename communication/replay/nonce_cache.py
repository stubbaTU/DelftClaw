"""Sliding-window nonce cache used on every receive.

A frame's ``nonce`` is admitted iff it has not been seen in the last
``window_ms`` milliseconds. Older entries are evicted lazily on each ``add``.
"""

from __future__ import annotations

from collections import OrderedDict


class NonceCache:
    """Bounded LRU-style cache mapping nonce → first-seen timestamp.

    ``add`` returns ``True`` when the nonce is fresh and was inserted, ``False``
    when it was already present (a replay). Callers should treat ``False`` as
    a hard failure and raise :class:`shared.errors.ReplayDetected`.
    """

    def __init__(self, window_ms: int = 5 * 60 * 1000, max_entries: int = 100_000) -> None:
        self._window_ms = window_ms
        self._max_entries = max_entries
        self._seen: "OrderedDict[bytes, int]" = OrderedDict()

    def add(self, nonce: bytes, ts_ms: int) -> bool:
        self._evict(now_ms=ts_ms)
        if nonce in self._seen:
            return False
        self._seen[nonce] = ts_ms
        if len(self._seen) > self._max_entries:
            self._seen.popitem(last=False)
        return True

    def _evict(self, now_ms: int) -> None:
        threshold = now_ms - self._window_ms
        while self._seen:
            oldest_nonce, oldest_ts = next(iter(self._seen.items()))
            if oldest_ts >= threshold:
                break
            self._seen.popitem(last=False)
