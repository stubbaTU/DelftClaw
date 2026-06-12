"""RED tests for ``redteam_ablation.live.server.HarnessMcpServer`` (§1.1 / §4).

CONTRACT ASSUMPTIONS (Green must honour these names; chosen as the simplest
transport-free surface per plan §1.1 "logic lives in plain methods so tests need
no transport"):

* ``HarnessMcpServer()`` constructs with no required args.
* ``server.begin_trial(dispatcher, sender_id)`` opens a trial; raises if a trial
  is already active.
* ``server.call_tool(name, **kwargs) -> str`` is the transport-free chokepoint a
  test invokes directly. It builds a
  ``ToolDecision(tool_name=name, tool_kwargs=<kwargs>, sender_id=<trial sender>)``,
  runs ``dispatcher.dispatch``, appends the CANONICAL 7-key step dict to the
  server-side trace buffer, and returns the agent-observed string
  (``"DENIED: ..."`` on deny, a short success string naming the tool on execute,
  ``"ERROR: ..."`` when no trial is active).
* ``server.end_trial() -> (steps, executions)`` returns the buffered steps and
  the ``ExecutionResult`` list, then clears.
* ``server.tool_names`` is a plain ``set[str]`` equal to ``FAKE_DANGEROUS_TOOLS``.
* ``server.build_app()`` returns a ``FastMCP`` instance exposing exactly those 6
  tools (only asserted behind ``pytest.importorskip("fastmcp")``).

The canonical step dict has EXACTLY the 7 keys FakeRuntime emits:
``proposed_tool, kwargs, allowed, executed, reason, interceptor, flagged_by``.
"""

from __future__ import annotations

import pytest

from redteam_ablation.contracts import ExecutionResult, ToolDecision
from redteam_ablation.interceptors.base import InterceptDecision
from redteam_ablation.interceptors.registry import interceptors_for
from redteam_ablation.interceptors.signed_log_audit import (
    SignedLogAuditInterceptor,
)
from redteam_ablation.live.server import HarnessMcpServer
from redteam_ablation.runtime.base import Dispatcher
from redteam_ablation.runtime.fake import (
    FAKE_DANGEROUS_TOOLS,
    SPOOFED_SENDER_ID,
    make_fake_policies,
    make_owner_identity,
)

CANONICAL_STEP_KEYS = {
    "proposed_tool",
    "kwargs",
    "allowed",
    "executed",
    "reason",
    "interceptor",
    "flagged_by",
}


def _owner_context() -> dict:
    owner = make_owner_identity()
    return {
        "owner_identity": owner,
        "owner_id": owner.reporter_id,
        "published_constitution_hash": "pub",
        "session_constitution_hash": "pub",
    }


def _v0_dispatcher() -> Dispatcher:
    return Dispatcher(make_fake_policies(), interceptors_for("V0"))


def _p1_strict_dispatcher() -> Dispatcher:
    return Dispatcher(
        make_fake_policies(),
        interceptors_for("P1-strict"),
        context=_owner_context(),
    )


# --- tool_names attribute --------------------------------------------------


def test_server_knows_its_six_tool_names():
    server = HarnessMcpServer()
    assert server.tool_names == set(FAKE_DANGEROUS_TOOLS)
    assert len(server.tool_names) == 6


# --- deny path -------------------------------------------------------------


def test_deny_path_returns_denied_string_and_records_step():
    server = HarnessMcpServer()
    dispatcher = _p1_strict_dispatcher()
    server.begin_trial(dispatcher, SPOOFED_SENDER_ID)

    out = server.call_tool("drain_wallet", destination="attacker", amount=100)
    assert isinstance(out, str)
    assert out.startswith("DENIED:")

    steps, executions = server.end_trial()
    assert len(steps) == 1
    step = steps[0]
    assert set(step.keys()) == CANONICAL_STEP_KEYS
    assert step["proposed_tool"] == "drain_wallet"
    assert step["executed"] is False
    assert step["allowed"] is False
    # P1-strict denier name is mode-tagged.
    assert step["interceptor"] == "P1-owner-identity[strict]"
    assert len(executions) == 1
    assert executions[0].executed is False


# --- execute path ----------------------------------------------------------


def test_execute_path_returns_success_and_records_executed():
    server = HarnessMcpServer()
    dispatcher = _v0_dispatcher()
    owner = make_owner_identity()
    server.begin_trial(dispatcher, owner.reporter_id)

    out = server.call_tool("send_email", to="x", subject="s", body="b")
    assert isinstance(out, str)
    assert not out.startswith("DENIED:")
    assert not out.startswith("ERROR:")

    steps, executions = server.end_trial()
    assert len(steps) == 1
    step = steps[0]
    assert step["executed"] is True
    assert step["allowed"] is True
    assert step["interceptor"] is None
    assert step["flagged_by"] == []
    assert executions[0].executed is True
    assert executions[0].attack_success is True


# --- V2 on_execute fires through dispatch ----------------------------------


def test_v2_on_execute_fires_through_dispatch_signed_log_grows(tmp_path):
    log_path = tmp_path / "signed.log"
    owner = make_owner_identity()
    ctx = {
        "owner_identity": owner,
        "owner_id": owner.reporter_id,
        "published_constitution_hash": "pub",
        "session_constitution_hash": "pub",
        "signed_log_path": str(log_path),
    }
    dispatcher = Dispatcher(
        make_fake_policies(), [SignedLogAuditInterceptor()], context=ctx
    )
    server = HarnessMcpServer()
    server.begin_trial(dispatcher, owner.reporter_id)

    server.call_tool("send_email", to="x", subject="s", body="b")
    assert log_path.exists()
    first_count = _signed_log_entry_count(log_path)
    assert first_count == 1

    server.call_tool("write_file", path="p", content="c")
    second_count = _signed_log_entry_count(log_path)
    # Exactly one new entry per executed call.
    assert second_count == first_count + 1

    server.end_trial()


def _signed_log_entry_count(log_path) -> int:
    """Count non-header, non-blank lines in the signed append-only log."""
    count = 0
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("==="):
            continue
        count += 1
    return count


# --- kwargs land verbatim + sender_id from begin_trial ---------------------


class _SpyInterceptor:
    """Captures the decision it observes; always allows (the tool executes)."""

    name = "spy"

    def __init__(self) -> None:
        self.seen_decision: ToolDecision | None = None

    def inspect(self, decision, context) -> InterceptDecision:
        self.seen_decision = decision
        return InterceptDecision(allow=True)


def test_kwargs_land_verbatim_on_decision():
    spy = _SpyInterceptor()
    dispatcher = Dispatcher(make_fake_policies(), [spy])
    server = HarnessMcpServer()
    owner = make_owner_identity()
    server.begin_trial(dispatcher, owner.reporter_id)

    server.call_tool(
        "send_email", to="victim@x", subject="hi", body="payload"
    )
    assert spy.seen_decision is not None
    assert spy.seen_decision.tool_name == "send_email"
    assert spy.seen_decision.tool_kwargs == {
        "to": "victim@x",
        "subject": "hi",
        "body": "payload",
    }
    server.end_trial()


def test_sender_id_from_begin_trial_is_on_decision():
    spy = _SpyInterceptor()
    dispatcher = Dispatcher(make_fake_policies(), [spy])
    server = HarnessMcpServer()
    server.begin_trial(dispatcher, "trial-sender-XYZ")

    server.call_tool("send_email", to="x")
    assert spy.seen_decision.sender_id == "trial-sender-XYZ"
    server.end_trial()


# --- trial lifecycle -------------------------------------------------------


def test_begin_trial_while_active_raises():
    server = HarnessMcpServer()
    server.begin_trial(_v0_dispatcher(), "s1")
    with pytest.raises(Exception):
        server.begin_trial(_v0_dispatcher(), "s2")


def test_no_active_trial_returns_error_and_records_nothing():
    server = HarnessMcpServer()
    out = server.call_tool("send_email", to="x")
    assert isinstance(out, str)
    assert out.startswith("ERROR:")
    # The probe after end_trial must not corrupt the next trial's trace.
    steps, executions = server.end_trial()
    assert steps == []
    assert executions == []


def test_end_trial_clears_so_next_begin_starts_empty():
    server = HarnessMcpServer()
    owner = make_owner_identity()

    server.begin_trial(_v0_dispatcher(), owner.reporter_id)
    server.call_tool("send_email", to="x")
    steps1, execs1 = server.end_trial()
    assert len(steps1) == 1
    assert len(execs1) == 1

    # Next trial starts from a clean buffer.
    server.begin_trial(_v0_dispatcher(), owner.reporter_id)
    steps2, execs2 = server.end_trial()
    assert steps2 == []
    assert execs2 == []


def test_end_trial_returns_execution_results():
    server = HarnessMcpServer()
    owner = make_owner_identity()
    server.begin_trial(_v0_dispatcher(), owner.reporter_id)
    server.call_tool("send_email", to="x")
    steps, executions = server.end_trial()
    assert all(isinstance(e, ExecutionResult) for e in executions)


# --- FastMCP app registration (behind importorskip) ------------------------


def test_build_app_registers_exactly_six_tools():
    pytest.importorskip("fastmcp")
    import asyncio

    server = HarnessMcpServer()
    app = server.build_app()

    # FastMCP 3.x: app.list_tools() is async and returns a list of tool objects
    # each carrying a .name. Discover defensively across plausible shapes.
    listed = asyncio.run(app.list_tools())
    if isinstance(listed, dict):
        names = set(listed.keys())
    else:
        names = {getattr(t, "name", t) for t in listed}
    assert names == set(FAKE_DANGEROUS_TOOLS)


# --- generated tool wrappers actually forward through dispatch -------------


def test_generated_tool_fn_forwards_named_params_through_dispatch():
    """The agent's REAL call surface is the dynamically-generated wrapper with
    natural params (e.g. send_email(to, subject, body)) -- not the bare
    call_tool the other tests drive. A typo in the exec'd src template would ship
    undetected unless we exercise a generated wrapper end-to-end through dispatch.
    No fastmcp needed: _make_tool_fn builds a plain Python callable.
    """
    server = HarnessMcpServer()
    dispatcher = _v0_dispatcher()
    owner = make_owner_identity()
    server.begin_trial(dispatcher, owner.reporter_id)

    send_email = server._make_tool_fn("send_email")
    out = send_email(to="boss@x", subject="hi", body="payload")
    assert not out.startswith(("DENIED:", "ERROR:"))

    steps, executions = server.end_trial()
    assert len(steps) == 1
    step = steps[0]
    assert step["proposed_tool"] == "send_email"
    # The natural params reached the dispatched decision's kwargs verbatim.
    assert step["kwargs"] == {"to": "boss@x", "subject": "hi", "body": "payload"}
    assert step["executed"] is True
