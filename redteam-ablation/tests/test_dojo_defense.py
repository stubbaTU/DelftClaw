"""IntegrityDefenseElement: the Substrate-2 adapter (plan 2026-06-10 §2.2).

The one-core-two-adapters rule: the defense element is an AgentDojo pipeline
element that REPLACES ``ToolsExecutor`` inside ``ToolsExecutionLoop`` and routes
EVERY proposed tool call through the SAME ``Dispatcher``/interceptors as the
offline harness (registry arms via ``interceptors_for``). Denials follow the
AgentDojo error-message convention (`error=` on the ChatToolResultMessage; the
episode continues); executions delegate to AgentDojo's ``FunctionsRuntime``
so P2's ``on_execute`` signed-log hook fires naturally.

Context synthesis (plan §2.2): all calls carry ``sender_id`` = the session
sender, which DEFAULTS to the owner (the orthogonality-by-construction of the
Behaviour control). Tests stage violations by configuring a non-owner
``sender_id`` (P1) or a diverged ``session_constitution_hash`` (P3) — the
calibration knobs, not the production default.
"""

from __future__ import annotations

import pytest

from agentdojo.agent_pipeline import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.functions_runtime import FunctionsRuntime

from redteam_ablation.metrics.alr import owner_task_denied
from redteam_ablation.primitives.signed_log import SignedAppendOnlyLog
from redteam_ablation.runtime.fake import make_owner_identity
from redteam_ablation.substrates.agentdojo_native.defense import (
    IntegrityDefenseElement,
)

from tests.agentdojo_stub import STUB_TOOLS, FakeLLM, StubEnv, tool_call

OWNER = make_owner_identity()

# The FakeRuntime/EpisodeResult trace-step key set (plan §2.2: the element
# accumulates the same trace shape so ALR/judging code is substrate-agnostic).
TRACE_STEP_KEYS = {
    "proposed_tool",
    "kwargs",
    "allowed",
    "executed",
    "reason",
    "interceptor",
    "flagged_by",
}


def _element(arm: str, **overrides) -> IntegrityDefenseElement:
    """Build a defense element with benign defaults (owner session)."""
    return IntegrityDefenseElement(arm, owner_identity=OWNER, **overrides)


def _run_one(element, calls, env=None, llm_turns=None):
    """Drive one scripted episode: LLM proposes ``calls``, loop executes."""
    env = env if env is not None else StubEnv()
    runtime = FunctionsRuntime(list(STUB_TOOLS))
    llm = FakeLLM(llm_turns if llm_turns is not None else [calls])
    loop = ToolsExecutionLoop([element, llm])
    # Seed: the LLM's first scripted turn, as if emitted by a prior llm element.
    query, runtime, env, messages, extra = llm.query("task", runtime, env, [])
    query, runtime, env, messages, extra = loop.query(
        query, runtime, env, messages, extra
    )
    return env, messages


def _tool_messages(messages):
    return [m for m in messages if m["role"] == "tool"]


# --- pipeline-element contract -------------------------------------------------


def test_is_a_base_pipeline_element():
    assert isinstance(_element("V0"), BasePipelineElement)


def test_noop_when_last_message_has_no_tool_calls():
    """Same iteration contract as ToolsExecutor: nothing to execute -> no-op."""
    element = _element("V0")
    runtime = FunctionsRuntime(list(STUB_TOOLS))
    env = StubEnv()
    messages = [
        {"role": "assistant", "content": [], "tool_calls": None},
    ]
    _, _, _, out_messages, _ = element.query("q", runtime, env, messages)
    assert list(out_messages) == messages
    assert element.tool_call_trace == []


# --- V0: execution path ----------------------------------------------------------


def test_v0_executes_tool_and_mutates_env():
    element = _element("V0")
    env, messages = _run_one(element, [tool_call("add_note", {"content": "beta"})])
    assert "beta" in env.notes.items
    (result_msg,) = _tool_messages(messages)
    assert result_msg["error"] is None
    assert "added: beta" in str(result_msg["content"])


def test_every_call_routed_through_dispatcher_exactly_once():
    """One trace step per proposed call -- the dispatch chokepoint property."""
    element = _element("V0")
    env, messages = _run_one(
        element,
        [tool_call("read_notes"), tool_call("add_note", {"content": "beta"})],
    )
    assert [s["proposed_tool"] for s in element.tool_call_trace] == [
        "read_notes",
        "add_note",
    ]
    assert all(set(s) == TRACE_STEP_KEYS for s in element.tool_call_trace)
    assert all(s["executed"] for s in element.tool_call_trace)


def test_decision_carries_owner_sender_by_default():
    """Context synthesis: the session sender IS the owner by default, so P1
    passes by construction (the orthogonality the Behaviour control needs)."""
    element = _element("P1-strict")
    env, messages = _run_one(element, [tool_call("read_notes")])
    (step,) = element.tool_call_trace
    assert step["executed"] is True
    assert step["interceptor"] is None


# --- strict arm: deny path --------------------------------------------------------


def test_strict_denial_blocks_execution_and_reports_error():
    """A non-owner session sender under P1-strict: the tool must NOT execute,
    the model sees the denial via the error= convention, the episode continues
    to the LLM's next scripted turn."""
    element = _element("P1-strict", sender_id="not-the-owner")
    env, messages = _run_one(
        element,
        [tool_call("add_note", {"content": "beta"})],
        llm_turns=[[tool_call("add_note", {"content": "beta"})], "ok, denied"],
    )
    # Not executed: env unchanged.
    assert "beta" not in env.notes.items
    (result_msg,) = _tool_messages(messages)
    assert result_msg["error"] is not None
    assert "P1-owner-identity[strict]" in result_msg["error"]
    # Episode continued: the LLM's follow-up text message was emitted.
    assert messages[-1]["role"] == "assistant"
    # Trace records the denial attributably.
    (step,) = element.tool_call_trace
    assert step["allowed"] is False
    assert step["executed"] is False
    assert step["interceptor"] == "P1-owner-identity[strict]"
    assert owner_task_denied(element.tool_call_trace) is True


def test_p3_strict_denies_on_diverged_constitution():
    element = _element(
        "P3-strict", session_constitution_hash="not-the-published-hash"
    )
    env, messages = _run_one(element, [tool_call("read_notes")])
    (step,) = element.tool_call_trace
    assert step["executed"] is False
    assert step["interceptor"] == "P3-constitution-hash[strict]"


# --- audit twin: detection-mirror ---------------------------------------------------


def test_audit_twin_executes_and_flags():
    """The audit mirror of the strict deny: same violation, tool EXECUTES,
    detection lands in flagged_by (plan §1.4's detection-mirror, on Substrate 2)."""
    element = _element("P1-audit", sender_id="not-the-owner")
    env, messages = _run_one(element, [tool_call("add_note", {"content": "beta"})])
    assert "beta" in env.notes.items  # executed
    (step,) = element.tool_call_trace
    assert step["allowed"] is True
    assert step["executed"] is True
    assert step["flagged_by"] == ["P1-owner-identity[audit]"]
    assert owner_task_denied(element.tool_call_trace) is False
    (result_msg,) = _tool_messages(messages)
    assert result_msg["error"] is None


@pytest.mark.parametrize(
    "arm, override",
    [
        ("P1-audit", {"sender_id": "not-the-owner"}),
        ("P3-audit", {"session_constitution_hash": "diverged"}),
    ],
)
def test_audit_arms_never_deny(arm, override):
    element = _element(arm, **override)
    env, messages = _run_one(element, [tool_call("read_notes")])
    (step,) = element.tool_call_trace
    assert step["executed"] is True
    assert step["interceptor"] is None
    assert step["flagged_by"]  # detection recorded


# --- P2: signed log on the execution path ---------------------------------------------


def test_p2_arm_signs_every_executed_call(tmp_path):
    log_path = tmp_path / "signed_dojo.log"
    element = _element("P2-audit", signed_log_path=str(log_path))
    env, messages = _run_one(
        element,
        [tool_call("read_notes"), tool_call("add_note", {"content": "beta"})],
    )
    log = SignedAppendOnlyLog(identity=OWNER, log_path=str(log_path))
    ok, errors = log.verify_integrity()
    assert ok and errors == []
    entries = log.read_entries()
    assert [e["action"] for e in entries] == ["read_notes", "add_note"]


# --- agentdojo conventions preserved ---------------------------------------------------


def test_unknown_tool_keeps_agentdojo_error_convention():
    """An LLM-proposed unknown tool gets agentdojo's own error message and is
    NOT an interceptor denial (ALR honesty: capability gap, not a veto)."""
    element = _element("P1-strict")
    env, messages = _run_one(element, [tool_call("no_such_tool")])
    (result_msg,) = _tool_messages(messages)
    assert result_msg["error"] == "Invalid tool no_such_tool provided."
    (step,) = element.tool_call_trace
    assert step["executed"] is False
    assert step["interceptor"] is None
    assert owner_task_denied(element.tool_call_trace) is False


def test_tool_error_propagates_as_error_message_not_crash():
    """A tool that errors internally (bad args) follows the run_function
    error-string convention; the episode does not crash."""
    element = _element("V0")
    env, messages = _run_one(
        element, [tool_call("add_note", {"wrong_arg": 1})]
    )
    (result_msg,) = _tool_messages(messages)
    assert result_msg["error"] is not None
    assert "ValidationError" in result_msg["error"]


# --- constructor contract ---------------------------------------------------------------


def test_unknown_arm_fails_loudly():
    with pytest.raises(KeyError):
        _element("no-such-arm")
