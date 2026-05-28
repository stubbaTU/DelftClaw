from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from security.agentdojo_vukzero.tool_mapping import AGENTDOJO_TOOL_MAP, get_tool_mapping
from security.permissions.models import Capability


EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
QUOTED_RE = re.compile(r"['\"]([^'\"]{2,120})['\"]")


@dataclass(frozen=True)
class AgentDojoCapabilityContext:
    subject_id: str
    task_id: str
    user_task_text: str


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
) -> list[Capability]:
    text = user_task_to_text(user_task)
    ctx = AgentDojoCapabilityContext(subject_id=subject_id, task_id=task_id, user_task_text=text)
    capabilities: list[Capability] = []
    for tool_name, raw in AGENTDOJO_TOOL_MAP.items():
        if not raw.get("requires_capability"):
            continue
        if not _task_authorizes_tool(text, tool_name):
            continue
        mapping = get_tool_mapping(tool_name)
        if mapping is None:
            continue
        capabilities.append(Capability(
            capability_id=f"cap_{task_id}_{tool_name}",
            subject_id=subject_id,
            allowed_action=mapping.action,
            resource_id=mapping.resource_id,
            resource_label=mapping.resource_label,
            task_id=task_id,
            constraints=_constraints_for_tool(ctx, tool_name),
        ))
    return capabilities


def _task_authorizes_tool(text: str, tool_name: str) -> bool:
    lowered = text.lower()
    if tool_name == "send_email":
        return "email" in lowered and any(word in lowered for word in ("send", "reply", "forward"))
    if tool_name == "share_file":
        return "share" in lowered and "file" in lowered
    if tool_name in {"create_calendar_event", "cancel_calendar_event", "reschedule_calendar_event", "add_calendar_event_participants"}:
        return any(word in lowered for word in ("calendar", "meeting", "event", "schedule", "reschedule", "cancel", "invite"))
    if tool_name in {"create_file", "append_to_file", "delete_file"}:
        action = tool_name.split("_", 1)[0]
        return "file" in lowered and action in lowered
    if tool_name in {"send_slack_message", "send_money", "transfer_money", "book_flight", "book_hotel"}:
        return any(token in lowered for token in tool_name.split("_"))
    return False


def _constraints_for_tool(ctx: AgentDojoCapabilityContext, tool_name: str) -> dict[str, Any]:
    text = ctx.user_task_text
    emails = sorted(set(EMAIL_RE.findall(text)))
    quotes = QUOTED_RE.findall(text)
    constraints: dict[str, Any] = {"tool_name": tool_name}
    if emails:
        constraints["allowed_recipients"] = emails
        constraints["allowed_participants"] = emails
    if quotes:
        constraints["quoted_values"] = quotes
        if tool_name == "send_email":
            constraints["allowed_subject_or_body_contains"] = quotes
        if tool_name in {"share_file", "create_file", "append_to_file", "delete_file"}:
            constraints["allowed_file_refs"] = quotes
        if "calendar" in tool_name or "event" in tool_name:
            constraints["allowed_calendar_text"] = quotes
    return constraints
