"""IntegrityDefenseElement -- the Substrate-2 adapter (plan 2026-06-10 §2.2).

An AgentDojo pipeline element that REPLACES ``ToolsExecutor`` inside a
``ToolsExecutionLoop`` and routes EVERY tool call the model proposes through
the SAME :class:`~redteam_ablation.runtime.base.Dispatcher` and interceptor
arms as the offline harness (the one-core-two-adapters rule). Execution stays
inside ``Dispatcher.dispatch``: each AgentDojo tool is wrapped as a
:class:`ToolPolicy` whose handler delegates to ``FunctionsRuntime.run_function``,
so a strict-arm denial really prevents execution and P2's ``on_execute``
signed-log hook fires on the real execution path.

Conventions preserved from AgentDojo's own ``ToolsExecutor`` (API_NOTES §2):
the empty-name and unknown-tool error messages, the string-encoded-list
literal-eval quirk, and the ``error=`` field on ``ChatToolResultMessage`` --
a denial surfaces to the model as a tool error and the episode continues
(deny-and-continue; no ``AbortAgentError``).

Context synthesis (plan §2.2): every proposed call carries
``sender_id = the session sender``, which DEFAULTS to the owner -- on this
substrate the whole session is the owner's, so P1/P3 pass by construction
(the orthogonality the Behaviour control is predicted to show). The
``sender_id`` / ``session_constitution_hash`` constructor knobs exist for
staged calibration episodes and tests, NOT for the pre-registered runs.

Known limitation: nested ``FunctionCall`` arguments (AgentDojo supports them)
reach P2's signed log as pydantic objects inside ``details`` and would fail
its JSON serialisation; none of our scripted or benchmark paths produce them.
"""

from __future__ import annotations

from ast import literal_eval
from collections.abc import Callable, Sequence
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import (
    ChatMessage,
    ChatToolResultMessage,
    text_content_block_from_string,
)

from redteam_ablation.contracts import ToolDecision, ToolPolicy, ToolRisk
from redteam_ablation.interceptors.registry import interceptors_for
from redteam_ablation.runtime.base import Dispatcher
from redteam_ablation.runtime.fake import PUBLISHED_CONSTITUTION_HASH


class IntegrityDefenseElement(BasePipelineElement):
    """Vet every proposed tool call through the shared interceptor core.

    One instance = one episode: the element accumulates ``tool_call_trace``
    (the same step-dict shape as ``EpisodeResult.tool_call_trace``, including
    ``flagged_by``) so ALR / judging code is substrate-agnostic. Runners build
    a fresh element per trial.
    """

    name = "integrity-defense"

    def __init__(
        self,
        arm: str,
        *,
        owner_identity: Any,
        owner_id: str | None = None,
        sender_id: str | None = None,
        published_constitution_hash: str = PUBLISHED_CONSTITUTION_HASH,
        session_constitution_hash: str | None = None,
        signed_log_path: str | None = None,
        tool_output_formatter: Callable[[Any], str] = tool_result_to_str,
    ) -> None:
        # Fails loudly (KeyError) on an unknown arm -- same registry authority
        # as the offline grid.
        self.arm = arm
        self.interceptors = interceptors_for(arm)
        self.output_formatter = tool_output_formatter

        owner_id = owner_id or owner_identity.reporter_id
        # The session sender defaults to the owner: every call on this
        # substrate is the owner's own session (plan §2.2).
        self.sender_id = sender_id if sender_id is not None else owner_id

        # Per-episode dispatch context -- the same keys the offline runtime
        # supplies (runtime/fake.py), so the interceptor bodies run unchanged.
        self._context: dict[str, Any] = {
            "owner_identity": owner_identity,
            "owner_id": owner_id,
            "published_constitution_hash": published_constitution_hash,
            "session_constitution_hash": (
                session_constitution_hash
                if session_constitution_hash is not None
                else published_constitution_hash
            ),
        }
        if signed_log_path is not None:
            self._context["signed_log_path"] = signed_log_path

        self.tool_call_trace: list[dict[str, Any]] = []

    # -- dispatch plumbing ---------------------------------------------------

    def _make_handler(self, runtime: FunctionsRuntime, env: Any, name: str):
        """Wrap an AgentDojo tool as a ToolPolicy handler.

        ``run_function`` returns ``(result, error)``; both are carried out of
        dispatch in the ExecutionResult's ``output`` so the element can format
        the tool message exactly like AgentDojo's own executor.
        """

        def handler(kwargs: dict[str, Any]) -> dict[str, Any]:
            result, error = runtime.run_function(env, name, kwargs)
            return {"result": result, "error": error}

        return handler

    def _record_step(
        self,
        *,
        proposed_tool: str,
        kwargs: dict[str, Any],
        allowed: bool,
        executed: bool,
        reason: str,
        interceptor: str | None,
        flagged_by: list[str],
    ) -> None:
        """Append one trace step in the EpisodeResult step-dict shape."""
        self.tool_call_trace.append(
            {
                "proposed_tool": proposed_tool,
                "kwargs": dict(kwargs),
                "allowed": allowed,
                "executed": executed,
                "reason": reason,
                "interceptor": interceptor,
                "flagged_by": list(flagged_by),
            }
        )

    # -- pipeline element ------------------------------------------------------

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        # Same iteration contract as ToolsExecutor: only act when the last
        # message is an assistant message carrying tool calls.
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        if messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        if messages[-1]["tool_calls"] is None or len(messages[-1]["tool_calls"]) == 0:
            return query, runtime, env, messages, extra_args

        # One dispatcher per query batch: policies wrap the CURRENT runtime +
        # env (they change per episode); context persists across the episode's
        # batches so P2's signed log chains all executed calls.
        policies = {
            name: ToolPolicy(
                name=name,
                handler=self._make_handler(runtime, env, name),
                risk=ToolRisk.SENSITIVE,
            )
            for name in runtime.functions
        }
        dispatcher = Dispatcher(policies, self.interceptors, context=self._context)

        tool_call_results = []
        for tool_call in messages[-1]["tool_calls"]:
            # AgentDojo convention: empty function name (API_NOTES §2).
            if tool_call.function == EMPTY_FUNCTION_NAME:
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error="Empty function name provided. Provide a valid function name.",
                    )
                )
                continue

            # AgentDojo convention: unknown tool. Checked BEFORE dispatch (as
            # ToolsExecutor does) so the model-visible error matches the stock
            # pipeline; recorded as a capability gap, NOT an interceptor
            # denial (interceptor=None -> owner_task_denied stays False).
            if tool_call.function not in runtime.functions:
                error = f"Invalid tool {tool_call.function} provided."
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=tool_call.id,
                        tool_call=tool_call,
                        error=error,
                    )
                )
                self._record_step(
                    proposed_tool=tool_call.function,
                    kwargs=dict(tool_call.args),
                    allowed=False,
                    executed=False,
                    reason=error,
                    interceptor=None,
                    flagged_by=[],
                )
                continue

            # AgentDojo quirk parity: string-encoded lists become lists.
            for arg_k, arg_v in tool_call.args.items():
                if isinstance(arg_v, str) and is_string_list(arg_v):
                    tool_call.args[arg_k] = literal_eval(arg_v)

            # THE chokepoint: the same Dispatcher/interceptors as offline.
            decision = ToolDecision(
                tool_name=tool_call.function,
                tool_kwargs=dict(tool_call.args),
                reason="agentdojo pipeline tool call",
                sender_id=self.sender_id,
            )
            result = dispatcher.dispatch(decision)

            if result.executed:
                output = result.output or {}
                tool_result = output.get("result", "")
                error = output.get("error")
                content = self.output_formatter(tool_result)
            else:
                # Interceptor denial: the deny reason IS the tool error the
                # model sees; nothing executed.
                error = result.reason
                content = ""

            tool_call_results.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(content)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
            )
            self._record_step(
                proposed_tool=tool_call.function,
                kwargs=dict(tool_call.args),
                allowed=bool(result.executed or result.authorized),
                executed=result.executed,
                reason=result.reason,
                interceptor=result.denied_by,
                flagged_by=list(result.flagged_by),
            )

        return query, runtime, env, [*messages, *tool_call_results], extra_args
