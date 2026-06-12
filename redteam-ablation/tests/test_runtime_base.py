"""Dispatcher + AgentRuntime ABC + EpisodeResult.

The dispatcher runs the registered interceptors over a ``ToolDecision``; if any
denies, the tool is NOT executed (this is the V1-V4 defence seam) and the result
records a non-success; otherwise it runs the ``ToolPolicy.handler`` and records
an executed, attack-successful ``ExecutionResult`` (the V0 vanilla path -- a
DANGEROUS tool firing unimpeded reproduces the V0 rows of ablation_run.log).
"""

import pytest

from redteam_ablation.contracts import (
    ExecutionResult,
    ToolDecision,
    ToolPolicy,
    ToolRisk,
)
from redteam_ablation.interceptors.base import Interceptor, InterceptDecision
from redteam_ablation.runtime.base import (
    AgentRuntime,
    Dispatcher,
    EpisodeResult,
)


class _Recorder:
    """Handler that records each invocation so we can assert execution."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, kwargs: dict):
        self.calls.append(kwargs)
        return {"ok": True, "kwargs": kwargs}


class _AllowAll:
    name = "allow_all"

    def inspect(self, decision: ToolDecision, context: dict) -> InterceptDecision:
        return InterceptDecision(allow=True, reason="allow_all")


class _DenyAll:
    name = "deny_all"

    def inspect(self, decision: ToolDecision, context: dict) -> InterceptDecision:
        return InterceptDecision(allow=False, reason="blocked by deny_all")


def _policy(handler) -> ToolPolicy:
    return ToolPolicy(
        name="drain_wallet",
        handler=handler,
        risk=ToolRisk.DANGEROUS,
    )


def _decision() -> ToolDecision:
    return ToolDecision(
        tool_name="drain_wallet",
        tool_kwargs={"amount": 100},
        reason="injected",
    )


# --- InterceptDecision -----------------------------------------------------


def test_intercept_decision_fields():
    d = InterceptDecision(allow=True, reason="ok")
    assert d.allow is True
    assert d.reason == "ok"


def test_concrete_interceptors_satisfy_protocol():
    assert isinstance(_AllowAll(), Interceptor)
    assert isinstance(_DenyAll(), Interceptor)


# --- Dispatcher ------------------------------------------------------------


def test_no_interceptors_executes_dangerous_tool():
    handler = _Recorder()
    disp = Dispatcher(policies={"drain_wallet": _policy(handler)}, interceptors=[])
    result = disp.dispatch(_decision())
    assert isinstance(result, ExecutionResult)
    assert result.executed is True
    assert result.attack_success is True
    assert result.authorized is True
    assert handler.calls == [{"amount": 100}]


def test_allow_all_interceptor_executes_tool():
    handler = _Recorder()
    disp = Dispatcher(
        policies={"drain_wallet": _policy(handler)},
        interceptors=[_AllowAll()],
    )
    result = disp.dispatch(_decision())
    assert result.executed is True
    assert result.attack_success is True
    assert len(handler.calls) == 1


def test_deny_interceptor_blocks_execution():
    handler = _Recorder()
    disp = Dispatcher(
        policies={"drain_wallet": _policy(handler)},
        interceptors=[_DenyAll()],
    )
    result = disp.dispatch(_decision())
    assert result.executed is False
    assert result.attack_success is False
    assert result.authorized is False
    assert "deny_all" in result.reason
    assert handler.calls == []  # handler never ran
    # The denier is carried OUT of dispatch on the result (Finding 3): no caller
    # need re-run inspect() to attribute the block.
    assert result.denied_by == "deny_all"


def test_executed_result_has_no_denier():
    handler = _Recorder()
    disp = Dispatcher(policies={"drain_wallet": _policy(handler)}, interceptors=[])
    result = disp.dispatch(_decision())
    assert result.executed is True
    assert result.denied_by is None


def test_first_denier_named_not_later_ones():
    handler = _Recorder()
    disp = Dispatcher(
        policies={"drain_wallet": _policy(handler)},
        interceptors=[_DenyAll(), _AllowAll()],
    )
    result = disp.dispatch(_decision())
    # The FIRST interceptor to deny is the one named.
    assert result.denied_by == "deny_all"


def test_unknown_tool_has_no_denier():
    handler = _Recorder()
    disp = Dispatcher(policies={"drain_wallet": _policy(handler)}, interceptors=[])
    result = disp.dispatch(ToolDecision(tool_name="no_such_tool"))
    # Not executed, but no interceptor denied it -- so no denier is attributed.
    assert result.executed is False
    assert result.denied_by is None


def test_first_deny_short_circuits_later_interceptors():
    handler = _Recorder()
    disp = Dispatcher(
        policies={"drain_wallet": _policy(handler)},
        interceptors=[_DenyAll(), _AllowAll()],
    )
    result = disp.dispatch(_decision())
    assert result.executed is False
    assert handler.calls == []


def test_unknown_tool_is_not_executed():
    handler = _Recorder()
    disp = Dispatcher(policies={"drain_wallet": _policy(handler)}, interceptors=[])
    result = disp.dispatch(ToolDecision(tool_name="no_such_tool"))
    assert result.executed is False
    assert result.attack_success is False
    assert handler.calls == []


def test_dispatch_records_requested_tool():
    handler = _Recorder()
    disp = Dispatcher(policies={"drain_wallet": _policy(handler)}, interceptors=[])
    result = disp.dispatch(_decision())
    assert result.requested_tool == "drain_wallet"


# --- EpisodeResult ---------------------------------------------------------


def test_episode_result_defaults_are_independent():
    a = EpisodeResult()
    b = EpisodeResult()
    a.tool_call_trace.append({"x": 1})
    a.executions.append("e")
    assert b.tool_call_trace == []
    assert b.executions == []


# --- AgentRuntime ABC ------------------------------------------------------


def test_agent_runtime_is_abstract():
    with pytest.raises(TypeError):
        AgentRuntime()  # type: ignore[abstract]


def test_subclass_can_implement_run_episode():
    class _Stub(AgentRuntime):
        def run_episode(self, *, system_prompt, tools, attack, seed, dispatcher):
            return EpisodeResult(tool_call_trace=[{"seed": seed}])

    runtime = _Stub()
    episode = runtime.run_episode(
        system_prompt="sp",
        tools=[],
        attack=object(),
        seed=42,
        dispatcher=Dispatcher(policies={}, interceptors=[]),
    )
    assert isinstance(episode, EpisodeResult)
    assert episode.tool_call_trace == [{"seed": 42}]
