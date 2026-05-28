from __future__ import annotations

import asyncio
import functools
import threading
from typing import Any, Callable

from security.agentdojo_vukzero.capability_builder import build_capabilities_from_user_task
from security.agentdojo_vukzero.tool_mapping import AGENTDOJO_TOOL_MAP, get_tool_mapping
from security.agentdojo_vukzero.validators import build_agentdojo_validator_registry
from security.agentdojo_vukzero.vukzero_agentdojo_policy import build_agentdojo_policy
from security.permissions import CapabilityStore, DecisionLog, PermissionEngine, Resource, ResourceRegistry, Subject, ToolBroker


def build_agentdojo_tool_broker(
    *,
    user_task: Any,
    subject: Subject | None = None,
    task_id: str = "agentdojo_task",
    current_round: int | None = None,
) -> tuple[ToolBroker, list[Any], DecisionLog]:
    subject = subject or Subject("agentdojo_agent", "normal_agent")
    capabilities = build_capabilities_from_user_task(user_task, subject_id=subject.subject_id, task_id=task_id)
    capability_store = CapabilityStore()
    for capability in capabilities:
        capability_store.issue(capability)
    registry = ResourceRegistry()
    for raw in AGENTDOJO_TOOL_MAP.values():
        registry.register(Resource(raw["resource_id"], raw["resource_label"]))
    validators = build_agentdojo_validator_registry(capabilities)
    decision_log = DecisionLog()
    engine = PermissionEngine(
        policy=build_agentdojo_policy(),
        resource_registry=registry,
        capability_store=capability_store,
        validator_registry=validators,
        decision_log=decision_log,
    )
    return ToolBroker(engine), capabilities, decision_log


def wrap_agentdojo_tool(
    original_tool: Callable[..., Any],
    tool_name: str,
    broker: ToolBroker,
    subject: Subject,
    task_id: str,
    current_round: int | None = None,
) -> Callable[..., Any]:
    mapping = get_tool_mapping(tool_name)
    if mapping is not None:
        broker.register_tool(
            tool_name,
            original_tool,
            mapping.action,
            lambda _args, resource_id=mapping.resource_id: resource_id,
            sink=mapping.sink,
        )

    @functools.wraps(original_tool)
    def wrapped_tool(**kwargs: Any) -> Any:
        if mapping is None:
            return {"ok": False, "error": "permission_denied", "reason": f"unknown AgentDojo tool: {tool_name}"}
        return _await_sync(broker.call_tool(
            subject=subject,
            tool_name=tool_name,
            args=dict(kwargs),
            task_id=task_id,
            current_round=current_round,
            input_taint="agentdojo_untrusted_environment",
        ))

    return wrapped_tool


def wrap_functions_runtime(
    runtime: Any,
    *,
    user_task: Any,
    subject_id: str = "agentdojo_agent",
    task_id: str = "agentdojo_task",
) -> tuple[Any, DecisionLog]:
    subject = Subject(subject_id, "normal_agent")
    broker, _capabilities, decision_log = build_agentdojo_tool_broker(
        user_task=user_task,
        subject=subject,
        task_id=task_id,
    )
    functions = getattr(runtime, "functions", None)
    if not isinstance(functions, dict):
        raise TypeError("AgentDojo runtime must expose a functions dictionary")
    wrapped_functions = {}
    for name, function in functions.items():
        original_callable = getattr(function, "run", function)
        wrapped_run = wrap_agentdojo_tool(original_callable, name, broker, subject, task_id)
        if hasattr(function, "model_copy"):
            wrapped_functions[name] = function.model_copy(update={"run": wrapped_run})
        elif hasattr(function, "copy"):
            wrapped_functions[name] = function.copy(update={"run": wrapped_run})
        else:
            setattr(function, "run", wrapped_run)
            wrapped_functions[name] = function
    if hasattr(runtime, "update_functions"):
        runtime.update_functions(wrapped_functions)
        return runtime, decision_log
    runtime.functions = wrapped_functions
    return runtime, decision_log


def make_vukzero_pipeline_element(
    user_task_text: str = "",
    task_id: str = "agentdojo_task",
    decision_logs: list[DecisionLog] | None = None,
) -> Any:
    try:
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.functions_runtime import EmptyEnv
    except ModuleNotFoundError as exc:
        raise RuntimeError("AgentDojo is not installed; cannot create pipeline element") from exc

    class VukZeroRuntimeWrapper(BasePipelineElement):  # type: ignore[misc]
        name = "vukzero_tool_broker"

        def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):  # type: ignore[no-untyped-def]
            extra_args = dict(extra_args or {})
            effective_task_id = task_id
            injection_task_id = ""
            try:
                from agentdojo.logging import Logger

                logger = Logger.get()
                context = getattr(logger, "context", {})
                effective_task_id = context.get("user_task_id") or effective_task_id
                injection_task_id = context.get("injection_task_id") or ""
            except Exception:
                pass
            wrapped_runtime, decision_log = wrap_functions_runtime(
                runtime,
                user_task=user_task_text or query,
                task_id=effective_task_id,
            )
            setattr(decision_log, "agentdojo_user_task_id", effective_task_id)
            setattr(decision_log, "agentdojo_injection_task_id", injection_task_id)
            if decision_logs is not None:
                decision_logs.append(decision_log)
            extra_args["vukzero_decision_log"] = decision_log
            return query, wrapped_runtime, env, messages, extra_args

    return VukZeroRuntimeWrapper()


def _await_sync(awaitable: Any) -> Any:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)
    if not loop.is_running():
        return loop.run_until_complete(awaitable)
    result: list[Any] = []
    error: list[BaseException] = []

    def runner() -> None:
        try:
            result.append(asyncio.run(awaitable))
        except BaseException as exc:  # pragma: no cover - defensive cross-loop bridge
            error.append(exc)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]
