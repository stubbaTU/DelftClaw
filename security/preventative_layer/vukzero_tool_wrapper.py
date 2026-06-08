from __future__ import annotations

import asyncio
import functools
import threading
from typing import Any, Callable, Mapping

from security.preventative_layer.permissions.effects import (
    EffectClass,
    ToolClassification,
    ToolSecuritySpec,
    classify_tool,
    tool_security_spec,
)
from security.preventative_layer.permissions.provenance import ProvenanceStore, validate_effect_provenance
from security.preventative_layer.permissions.validators import default_validator_registry
from security.preventative_layer.trusted_planner import build_task_capabilities
from security.preventative_layer.vukzero_agentdojo_policy import build_provenance_policy
from security.preventative_layer.permissions import CapabilityStore, DecisionLog, PermissionEngine, Resource, ResourceRegistry, Subject, ToolBroker


def build_agentdojo_tool_broker(
    *,
    user_task: Any,
    subject: Subject | None = None,
    task_id: str = "agentdojo_task",
    current_round: int | None = None,
    tool_specs: list[ToolSecuritySpec] | None = None,
    explicit_capability_tools: list[str] | None = None,
) -> tuple[ToolBroker, list[Any], DecisionLog, ProvenanceStore]:
    subject = subject or Subject("agentdojo_agent", "normal_agent")
    specs = list(tool_specs or [])
    classifications = {spec.name: classify_tool(spec) for spec in specs}
    capabilities = build_task_capabilities(
        str(user_task),
        specs,
        classifications,
        subject_id=subject.subject_id,
        task_id=task_id,
        explicit_tools=explicit_capability_tools,
    )
    provenance = ProvenanceStore(trusted_task_text=str(user_task))
    capability_store = CapabilityStore()
    for capability in capabilities:
        capability_store.issue(capability)
    registry = ResourceRegistry()
    for classification in classifications.values():
        registry.register(Resource(classification.resource_id, classification.resource_label))
    validators = default_validator_registry()
    validators.register(
        "effect_argument_provenance",
        lambda request: validate_effect_provenance(request, provenance, capabilities),
    )
    decision_log = DecisionLog()
    for capability in capabilities:
        decision_log.record_capability_grant(capability)
    engine = PermissionEngine(
        policy=build_provenance_policy(),
        resource_registry=registry,
        capability_store=capability_store,
        validator_registry=validators,
        decision_log=decision_log,
    )
    broker = ToolBroker(engine)
    setattr(broker, "tool_classifications", classifications)
    setattr(broker, "provenance_store", provenance)
    return broker, capabilities, decision_log, provenance


def wrap_agentdojo_tool(
    original_tool: Callable[..., Any],
    tool_name: str,
    broker: ToolBroker,
    subject: Subject,
    task_id: str,
    current_round: int | None = None,
    provenance_store: ProvenanceStore | None = None,
    classification: ToolClassification | None = None,
) -> Callable[..., Any]:
    classification = classification or classify_tool(ToolSecuritySpec(name=tool_name))
    broker.register_tool(
        tool_name,
        original_tool,
        classification.action,
        lambda _args, resource_id=classification.resource_id: resource_id,
        sink=classification.sink,
        effect_class=classification.effect_class.value,
        classification_source=classification.classification_source,
        neutral_args=classification.neutral_args,
        broadcast_sink=classification.broadcast_sink,
        allow_content_after_untrusted=classification.allow_content_after_untrusted,
    )

    @functools.wraps(original_tool)
    def wrapped_tool(**kwargs: Any) -> Any:
        result = _await_sync(broker.call_tool(
            subject=subject,
            tool_name=tool_name,
            args=dict(kwargs),
            task_id=task_id,
            current_round=current_round,
            input_taint="agentdojo_untrusted_environment",
        ))
        if (
            provenance_store is not None
            and classification.effect_class is not EffectClass.EFFECT
            and not _is_denied_result(result)
        ):
            provenance_store.record_read(
                classification.effect_class,
                result,
                call_args=dict(kwargs),
                tool_name=tool_name,
            )
        return result

    return wrapped_tool


def wrap_functions_runtime(
    runtime: Any,
    *,
    user_task: Any,
    subject_id: str = "agentdojo_agent",
    task_id: str = "agentdojo_task",
    trusted_tool_annotations: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[Any, DecisionLog]:
    subject = Subject(subject_id, "normal_agent")
    functions = getattr(runtime, "functions", None)
    if not isinstance(functions, dict):
        raise TypeError("AgentDojo runtime must expose a functions dictionary")
    annotations = trusted_tool_annotations or {}
    specs = [
        tool_security_spec(
            function,
            fallback_name=name,
            annotation_overrides=annotations.get(name),
        )
        for name, function in functions.items()
    ]
    broker, _capabilities, decision_log, provenance = build_agentdojo_tool_broker(
        user_task=user_task,
        subject=subject,
        task_id=task_id,
        tool_specs=specs,
    )
    classifications: dict[str, ToolClassification] = getattr(broker, "tool_classifications")
    wrapped_functions = {}
    for name, function in functions.items():
        original_callable = getattr(function, "run", function)
        wrapped_run = wrap_agentdojo_tool(
            original_callable,
            name,
            broker,
            subject,
            task_id,
            provenance_store=provenance,
            classification=classifications[name],
        )
        if hasattr(function, "model_copy"):
            wrapped_functions[name] = function.model_copy(update={"run": wrapped_run})
        elif hasattr(function, "copy"):
            wrapped_functions[name] = function.copy(update={"run": wrapped_run})
        else:
            setattr(function, "run", wrapped_run)
            wrapped_functions[name] = function
    if hasattr(runtime, "update_functions"):
        runtime.update_functions(wrapped_functions)
        setattr(decision_log, "provenance_store", provenance)
        setattr(decision_log, "tool_classifications", classifications)
        return runtime, decision_log
    runtime.functions = wrapped_functions
    setattr(decision_log, "provenance_store", provenance)
    setattr(decision_log, "tool_classifications", classifications)
    return runtime, decision_log


def make_vukzero_pipeline_element(
    user_task_text: str = "",
    task_id: str = "agentdojo_task",
    decision_logs: list[DecisionLog] | None = None,
    trusted_tool_annotations: Mapping[str, Mapping[str, Any]] | None = None,
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
                trusted_tool_annotations=trusted_tool_annotations,
            )
            setattr(decision_log, "agentdojo_user_task_id", effective_task_id)
            setattr(decision_log, "agentdojo_injection_task_id", injection_task_id)
            if decision_logs is not None:
                decision_logs.append(decision_log)
            extra_args["vukzero_decision_log"] = decision_log
            return query, wrapped_runtime, env, messages, extra_args

    return VukZeroRuntimeWrapper()


def make_vukzero_final_output_guard() -> Any:
    try:
        from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
        from agentdojo.functions_runtime import EmptyEnv
        from agentdojo.types import text_content_block_from_string
    except ModuleNotFoundError as exc:
        raise RuntimeError("AgentDojo is not installed; cannot create final output guard") from exc

    class VukZeroFinalOutputGuard(BasePipelineElement):  # type: ignore[misc]
        name = "vukzero_final_output_guard"

        def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):  # type: ignore[no-untyped-def]
            extra_args = dict(extra_args or {})
            decision_log = extra_args.get("vukzero_decision_log")
            entries = decision_log.entries() if decision_log is not None else []
            denied_effect = any(
                entry.get("action") == "effect" and entry.get("decision") == "deny"
                for entry in entries
            )
            if not denied_effect:
                return query, runtime, env, messages, extra_args
            if not messages or messages[-1].get("role") != "assistant":
                return query, runtime, env, messages, extra_args
            final_text = _message_text(messages[-1]).lower()
            if not _claims_denied_action_completed(final_text):
                return query, runtime, env, messages, extra_args
            guarded = dict(messages[-1])
            guarded["content"] = [text_content_block_from_string(
                "I blocked an unauthorized instruction from untrusted content and did not perform that action."
            )]
            extra_args["vukzero_final_output_blocked"] = True
            return query, runtime, env, [*messages[:-1], guarded], extra_args

    return VukZeroFinalOutputGuard()


def _message_text(message: Any) -> str:
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(str(block.get("content", "")) if isinstance(block, dict) else str(block) for block in content)
    return ""


def _claims_denied_action_completed(text: str) -> bool:
    return any(token in text for token in (
        "sent",
        "emailed",
        "deleted",
        "removed",
        "created",
        "scheduled",
        "shared",
        "transferred",
        "booked",
    ))


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


def _is_denied_result(result: Any) -> bool:
    return isinstance(result, dict) and result.get("error") == "permission_denied"
