from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from security.preventative_layer.permissions.effects import EffectClass, ToolClassification, ToolSecuritySpec
from security.preventative_layer.permissions.models import Capability
from security.preventative_layer.permissions.provenance import extract_task_literals


@dataclass(frozen=True)
class PlannedCapability:
    tool_name: str
    reason: str


ACTION_ALIASES = {
    "add": {"add", "attach", "include", "invite"},
    "append": {"append", "add", "write"},
    "book": {"book", "reserve", "schedule"},
    "broadcast": {"broadcast", "announce", "send"},
    "cancel": {"cancel", "remove", "delete"},
    "create": {"create", "make", "schedule", "add", "write"},
    "delete": {"delete", "remove", "erase", "cancel"},
    "donate": {"donate", "give", "contribute", "pay"},
    "join": {"join", "connect", "enroll"},
    "modify": {"modify", "change", "update", "edit"},
    "pay": {"pay", "send", "transfer", "donate"},
    "publish": {"publish", "post", "share"},
    "request": {"request", "ask", "obtain", "get"},
    "reschedule": {"reschedule", "move", "change", "update"},
    "send": {"send", "email", "reply", "forward", "message", "pay", "post", "transfer"},
    "set": {"set", "change", "update"},
    "share": {"share", "send", "publish"},
    "sign": {"sign", "authenticate", "prove"},
    "submit": {"submit", "send", "report"},
    "transfer": {"transfer", "send", "pay"},
    "update": {"update", "change", "edit", "modify"},
    "write": {"write", "create", "save", "append"},
}
OBJECT_ALIASES = {
    "calendar": {"calendar", "event", "meeting", "schedule", "appointment"},
    "event": {"calendar", "event", "meeting", "schedule", "appointment"},
    "email": {"email", "mail", "message"},
    "file": {"file", "document", "attachment"},
    "flight": {"flight", "travel", "trip"},
    "hotel": {"hotel", "travel", "accommodation"},
    "money": {"money", "payment", "funds", "transfer"},
    "message": {"message", "email", "mail", "notification"},
}


def build_task_capabilities(
    trusted_task: str,
    tool_specs: Iterable[ToolSecuritySpec],
    classifications: dict[str, ToolClassification],
    *,
    subject_id: str,
    task_id: str,
    explicit_tools: Iterable[str] | None = None,
) -> list[Capability]:
    """Build effect capabilities from trusted task text and trusted tool metadata.

    `explicit_tools` is the preferred production path for a signed/approved
    capability manifest. When absent, a deterministic metadata planner is used.
    """

    explicit = set(explicit_tools or ())
    task_tokens = set(_tokens(trusted_task))
    literals = sorted(extract_task_literals(trusted_task))
    capabilities: list[Capability] = []
    for spec in tool_specs:
        classification = classifications[spec.name]
        if classification.effect_class is not EffectClass.EFFECT:
            continue
        authorized, reason = (
            (True, "explicit trusted capability manifest")
            if spec.name in explicit
            else _task_authorizes_tool(task_tokens, spec)
        )
        if not authorized:
            continue
        constraints = {
            "tool_name": spec.name,
            "authorized_literals": literals,
            "planner_reason": reason,
        }
        max_uses = spec.annotations.get("max_uses")
        if isinstance(max_uses, int) and max_uses > 0:
            constraints["max_uses"] = max_uses
        capabilities.append(Capability(
            capability_id=f"cap_{task_id}_{spec.name}",
            subject_id=subject_id,
            allowed_action=classification.action,
            resource_id=classification.resource_id,
            resource_label=classification.resource_label,
            task_id=task_id,
            constraints=constraints,
        ))
    return capabilities


def _task_authorizes_tool(task_tokens: set[str], spec: ToolSecuritySpec) -> tuple[bool, str]:
    name_tokens = _tokens(spec.name)
    description_tokens = set(_tokens(spec.description))
    if not name_tokens:
        return False, "tool has no semantic metadata"

    action = name_tokens[0]
    action_terms = ACTION_ALIASES.get(action, {action})
    if not task_tokens.intersection(action_terms):
        return False, "trusted task does not authorize tool action"

    object_tokens = set(name_tokens[1:])
    if object_tokens:
        object_tokens -= _generic_tokens()
    else:
        object_tokens = description_tokens
        object_tokens -= _generic_tokens() | _all_action_tokens()
    expanded_objects = set(object_tokens)
    for token in object_tokens:
        expanded_objects.update(OBJECT_ALIASES.get(token, ()))
    if expanded_objects and not task_tokens.intersection(expanded_objects):
        return False, "trusted task does not reference tool object"
    return True, "trusted task action and object match tool metadata"


def _tokens(value: str) -> list[str]:
    expanded = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    return re.findall(r"[a-z0-9]+", expanded.lower())


def _generic_tokens() -> set[str]:
    return {
        "a",
        "an",
        "and",
        "available",
        "call",
        "for",
        "from",
        "in",
        "of",
        "on",
        "operation",
        "requested",
        "the",
        "this",
        "to",
        "tool",
        "with",
    }


def _all_action_tokens() -> set[str]:
    return set(ACTION_ALIASES) | {token for aliases in ACTION_ALIASES.values() for token in aliases}
