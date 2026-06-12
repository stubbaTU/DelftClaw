"""Interceptor port for the tool dispatcher.

A *variant* (V0-V4) is a named set of interceptors registered on the dispatcher,
not a fork-per-variant. An interceptor inspects a proposed :class:`ToolDecision`
before it is authorized to execute and returns an :class:`InterceptDecision`. The
dispatcher (``redteam_ablation.runtime.base.Dispatcher``) runs them in order and
denies execution as soon as one returns ``allow=False``.

This module defines only the *port* (the Protocol + the decision record). V0 is
the empty interceptor set (vanilla, no defence); the V1-V4 interceptor *bodies*
land in a later phase. The optional ``on_execute`` hook is the seam V2's
signed-append-only-log wrapping will use to observe executed tool calls; the
dispatcher calls it after a successful execution when an interceptor provides it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from redteam_ablation.contracts import ExecutionResult, ToolDecision


@dataclass(frozen=True)
class InterceptDecision:
    """An interceptor's verdict on a proposed tool call.

    ``allow=True`` lets the dispatcher proceed to the next interceptor (or, if
    this is the last, to executing the tool). ``allow=False`` denies execution;
    ``reason`` is recorded on the resulting :class:`ExecutionResult` and trace
    step for accountability. ``flagged=True`` is the audit-mode detection
    signal: the call proceeds, but the dispatcher records the flagging
    interceptor's name on the result's ``flagged_by`` (default ``False`` keeps
    every pre-ladder call site valid).
    """

    allow: bool
    reason: str = ""
    flagged: bool = False


@runtime_checkable
class Interceptor(Protocol):
    """Structural type every variant interceptor satisfies.

    Implementations expose a human-readable ``name`` (recorded in the trace so a
    denied step can be attributed to the defence that blocked it) and an
    ``inspect`` method invoked with the proposed decision and a mutable context
    dict (per-episode scratch space: identity, session config, prior trace).
    """

    name: str

    def inspect(
        self, decision: ToolDecision, context: dict[str, Any]
    ) -> InterceptDecision:
        """Return whether ``decision`` may proceed toward execution."""
        ...


def on_execute(
    interceptor: Interceptor,
    decision: ToolDecision,
    result: ExecutionResult,
    context: dict[str, Any],
) -> None:
    """Call ``interceptor.on_execute`` if it defines one (optional hook seam).

    Interceptors may optionally observe executed tool calls (e.g. V2's
    signed-append-only log appending an entry). The hook is optional, so the
    dispatcher routes through this helper rather than assuming it exists.
    """
    hook = getattr(interceptor, "on_execute", None)
    if callable(hook):
        hook(decision, result, context)
