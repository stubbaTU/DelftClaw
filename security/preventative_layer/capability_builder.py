from __future__ import annotations

from typing import Any, Iterable

from security.preventative_layer.permissions.effects import ToolSecuritySpec, classify_tool
from security.preventative_layer.permissions.models import Capability
from security.preventative_layer.trusted_planner import build_task_capabilities


def user_task_to_text(user_task: Any) -> str:
    if isinstance(user_task, str):
        return user_task
    for attr in ("PROMPT", "prompt", "instruction", "instructions", "text", "user_task", "description"):
        value = getattr(user_task, attr, None)
        if isinstance(value, str) and value.strip():
            return value
    return str(user_task)


def build_capabilities_from_user_task(
    user_task: Any,
    *,
    subject_id: str = "agentdojo_agent",
    task_id: str = "agentdojo_task",
    tool_specs: Iterable[ToolSecuritySpec],
    explicit_tools: Iterable[str] | None = None,
) -> list[Capability]:
    """Build capabilities from a trusted task and its actual tool catalog."""

    specs = list(tool_specs)
    classifications = {spec.name: classify_tool(spec) for spec in specs}
    return build_task_capabilities(
        user_task_to_text(user_task),
        specs,
        classifications,
        subject_id=subject_id,
        task_id=task_id,
        explicit_tools=explicit_tools,
    )
