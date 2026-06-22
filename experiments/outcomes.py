"""Outcome taxonomy for one SQ3 compile, with infrastructure isolation.

The old harness folded three very different events into a single "compile
failure": the endpoint was unreachable, the model emitted code that would not
load, and the model emitted code that loaded but failed its own worked examples.
Only the last two say anything about the model; the first is noise from the test
rig. This module separates them.

A single compile resolves to exactly one ``Outcome``:

  * ``INFRA_ERROR``        — the LLM endpoint failed (HTTP error, timeout,
                             connection drop). Retried with backoff first; if it
                             still fails it is excluded from every rate, never
                             counted as a model failure (invariant **I6**).
  * ``COMPILE_LOAD_FAIL``  — the generated source did not load: a sandbox
                             violation, a structural-contract breach, or a
                             community-id mismatch.
  * ``COMPILE_VECTOR_FAIL``— the source loaded but a worked example (the
                             descriptor's own test vector) did not round-trip.
  * ``OK``                 — loaded and every worked example passed; the source
                             is ready for the behavioural conformance/interop
                             stage.

Splitting load from vector failure is what the secondary results table needs
(the two columns the old single rate could not express); it is obtained for free
by compiling with ``defer_vector_check=True`` (``protocol/compiler.py``), which
records the vector result instead of raising on it.
"""

from __future__ import annotations

import socket
import time
import urllib.error
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from protocol.compiler import ProtocolCompileError, compile_overlay
from protocol.llm import LLMClient
from protocol.sandbox import SandboxError

# HTTPError is a subclass of URLError, so this tuple also catches it.
INFRA_EXCEPTIONS: tuple[type[BaseException], ...] = (
    urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError,
)


class Outcome(str, Enum):
    INFRA_ERROR = "infra_error"
    COMPILE_LOAD_FAIL = "compile_load_fail"
    COMPILE_VECTOR_FAIL = "compile_vector_fail"
    OK = "ok"

    # Behavioural outcomes (assigned by the conformance/interop stage, not by
    # ``compile_classified``) — kept here so the taxonomy is one closed set.
    CONFORMANCE_FAIL = "conformance_fail"
    INTEROP_FAIL = "interop_fail"
    PASS = "pass"


@dataclass(frozen=True)
class CompileResult:
    """The outcome of one classified compile. ``source`` is present iff the
    source loaded (``OK`` or ``COMPILE_VECTOR_FAIL``); ``vectors_passed`` is set
    whenever the source loaded."""
    outcome: Outcome
    source: str | None = None
    error: str | None = None
    vectors_passed: bool | None = None

    @property
    def loaded(self) -> bool:
        return self.outcome in (Outcome.OK, Outcome.COMPILE_VECTOR_FAIL)


def _backoff(attempt: int, cap_s: float = 15.0) -> float:
    return min(1.5 * (2 ** attempt), cap_s)


def compile_classified(
    md_text: str,
    client: LLMClient,
    *,
    infra_retries: int = 2,
    _sleep: Callable[[float], None] = time.sleep,
) -> CompileResult:
    """Compile ``md_text`` once and classify the result.

    Infrastructure failures are retried up to ``infra_retries`` times with
    exponential backoff (on top of the client's own 429/503 retry) before being
    recorded as ``INFRA_ERROR``. Load and vector failures are deterministic and
    not retried — re-asking the same model the same question is not what the
    deployed agent does, and would bias the rate.
    """
    for attempt in range(infra_retries + 1):
        try:
            compiled = compile_overlay(md_text, client, defer_vector_check=True)
        except INFRA_EXCEPTIONS as exc:
            if attempt < infra_retries:
                _sleep(_backoff(attempt))
                continue
            return CompileResult(Outcome.INFRA_ERROR, error=f"{type(exc).__name__}: {exc}")
        except (ProtocolCompileError, SandboxError) as exc:
            return CompileResult(Outcome.COMPILE_LOAD_FAIL, error=f"{type(exc).__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001 — any other load-time fault
            return CompileResult(Outcome.COMPILE_LOAD_FAIL, error=f"{type(exc).__name__}: {exc}")
        if compiled.test_vectors_passed is False:
            return CompileResult(
                Outcome.COMPILE_VECTOR_FAIL, source=compiled.source,
                error=compiled.test_vector_error, vectors_passed=False)
        return CompileResult(Outcome.OK, source=compiled.source, vectors_passed=True)

    raise AssertionError("unreachable: compile_classified retry loop")  # pragma: no cover
