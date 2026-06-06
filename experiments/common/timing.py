"""Minimal reusable timing helpers."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from time import perf_counter_ns
from typing import Callable, Iterator, TypeVar


T = TypeVar("T")


@dataclass
class Timer:
    start_ns: int = 0
    end_ns: int = 0

    @property
    def duration_ms(self) -> float:
        return (self.end_ns - self.start_ns) / 1_000_000


@contextmanager
def measure() -> Iterator[Timer]:
    timer = Timer(start_ns=perf_counter_ns())
    try:
        yield timer
    finally:
        timer.end_ns = perf_counter_ns()


def timed_call(callback: Callable[[], T]) -> tuple[T, float]:
    """Return a callback result and elapsed wall-clock duration in milliseconds."""

    start_ns = perf_counter_ns()
    result = callback()
    end_ns = perf_counter_ns()
    return result, (end_ns - start_ns) / 1_000_000
