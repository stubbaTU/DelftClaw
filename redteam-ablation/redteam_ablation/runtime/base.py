"""Tool dispatcher and the agent-runtime port.

The :class:`Dispatcher` is the single chokepoint every proposed tool call passes
through. It runs the variant's interceptors over a :class:`ToolDecision`; if any
denies, the tool is NOT executed (the V1-V4 defence seam) and a non-success
:class:`ExecutionResult` is returned. Otherwise it invokes the matching
:class:`ToolPolicy` handler and records an executed result -- a DANGEROUS tool
firing unimpeded under V0 (the empty interceptor set) is exactly the V0 row of
the surviving ``ablation_run.log``.

:class:`AgentRuntime` is the abstract port a concrete runtime (the deterministic
``FakeRuntime``; later the real ``OpenClawRuntime``) implements. It produces an
:class:`EpisodeResult` carrying the full tool-call trace and the executions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from redteam_ablation.contracts import (
    ExecutionResult,
    ToolDecision,
    ToolPolicy,
)
from redteam_ablation.interceptors.base import (
    Interceptor,
    on_execute as _fire_on_execute,
)


@dataclass
class EpisodeResult:
    """Outcome of one runtime episode (one trial).

    ``tool_call_trace`` holds one dict per proposed tool call with keys
    ``proposed_tool``, ``kwargs``, ``allowed``, ``executed``, ``reason``,
    ``interceptor`` (the name of the interceptor that denied, or ``None``) and
    ``flagged_by`` (the list of audit-mode flagging interceptor names).
    ``executions`` holds the :class:`ExecutionResult` for each dispatched call.
    """

    tool_call_trace: list[dict[str, Any]] = field(default_factory=list)
    executions: list[ExecutionResult] = field(default_factory=list)


class Dispatcher:
    """Authorization + execution chokepoint for one variant.

    ``policies`` maps tool name -> :class:`ToolPolicy`. ``interceptors`` is the
    ordered defence set for the variant (empty for V0). ``dispatch`` runs the
    interceptors then, if all allow and the tool is known, executes its handler.
    """

    def __init__(
        self,
        policies: dict[str, ToolPolicy],
        interceptors: list[Interceptor],
        context: dict[str, Any] | None = None,
    ) -> None:
        self.policies = policies
        self.interceptors = list(interceptors)
        # Per-episode scratch space handed to every interceptor (identity,
        # session config, accumulating trace). Defaults to a fresh dict.
        self.context: dict[str, Any] = context if context is not None else {}

    def dispatch(self, decision: ToolDecision) -> ExecutionResult:
        """Authorize and (if allowed) execute ``decision``'s tool.

        Interceptors run in order; the first denial short-circuits and blocks
        execution. An unknown tool is treated as not-executed (no handler to run)
        even though no interceptor objected.
        """
        # 1. Run the variant's interceptors; first denial wins. Audit-mode
        #    detections (verdict.flagged) are collected DURING the loop so flags
        #    raised before a later denial still land on the denied result
        #    (plan 2026-06-10 §1.2).
        flagged_by: list[str] = []
        for interceptor in self.interceptors:
            verdict = interceptor.inspect(decision, self.context)
            if verdict.flagged:
                flagged_by.append(interceptor.name)
            if not verdict.allow:
                return ExecutionResult(
                    requested_tool=decision.tool_name,
                    executed=False,
                    authorized=False,
                    attack_success=False,
                    reason=verdict.reason or f"denied by {interceptor.name}",
                    output=None,
                    payload_id=decision.payload_id,
                    sender_id=decision.sender_id,
                    # Carry the denier OUT of dispatch so callers attribute the
                    # block without re-running inspect (Finding 3). Stateful
                    # interceptors and V2's on_execute hook must be evaluated
                    # exactly once per call.
                    denied_by=interceptor.name,
                    flagged_by=tuple(flagged_by),
                )

        # 2. No interceptor denied. Resolve the policy; unknown tools cannot run.
        policy = self.policies.get(decision.tool_name)
        if policy is None:
            return ExecutionResult(
                requested_tool=decision.tool_name,
                executed=False,
                authorized=False,
                attack_success=False,
                reason=f"no policy registered for tool {decision.tool_name!r}",
                output=None,
                payload_id=decision.payload_id,
                sender_id=decision.sender_id,
                flagged_by=tuple(flagged_by),
            )

        # 3. Execute the handler. The tool ran; for a DANGEROUS target tool this
        #    is an attack success (the V0 vanilla path of ablation_run.log).
        output = policy.handler(decision.tool_kwargs)
        result = ExecutionResult(
            requested_tool=decision.tool_name,
            executed=True,
            authorized=True,
            attack_success=True,
            reason="executed",
            output=output,
            payload_id=decision.payload_id,
            sender_id=decision.sender_id,
            flagged_by=tuple(flagged_by),
        )

        # 4. Optional post-execution hook seam (V2 signed-log wrapping).
        for interceptor in self.interceptors:
            _fire_on_execute(interceptor, decision, result, self.context)

        return result


class AgentRuntime(ABC):
    """Abstract runtime port: turn an attack fixture into an episode.

    Concrete implementors: ``runtime.fake.FakeRuntime`` (deterministic, offline)
    and, in a later phase, ``runtime.openclaw.OpenClawRuntime`` (real OpenClaw +
    Sonnet 4.6). The runtime proposes tool calls to ``dispatcher.dispatch`` and
    assembles the resulting :class:`EpisodeResult`.
    """

    @abstractmethod
    def run_episode(
        self,
        *,
        system_prompt: str,
        tools: list[Any],
        attack: Any,
        seed: int,
        dispatcher: Dispatcher,
    ) -> EpisodeResult:
        """Run one trial of ``attack`` under ``seed`` against ``dispatcher``."""
        raise NotImplementedError
