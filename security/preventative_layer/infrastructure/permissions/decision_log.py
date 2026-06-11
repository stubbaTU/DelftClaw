from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security.preventative_layer.infrastructure.permissions.egress_guard import DEFAULT_SECRET_PATTERNS
from security.preventative_layer.infrastructure.permissions.models import Capability, PermissionDecision, PermissionRequest


class DecisionLog:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    def record(self, request: PermissionRequest, decision: PermissionDecision) -> None:
        self._entries.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request.request_id,
            "subject_id": request.subject.subject_id,
            "role": request.subject.role,
            "tool_name": request.tool_name,
            "action": request.action,
            "resource_id": request.resource_id,
            "resource_label": request.resource_label,
            "task_id": request.task_id,
            "sink": request.sink,
            "effect_class": request.effect_class,
            "classification_source": request.classification_source,
            "neutral_args": list(request.neutral_args),
            "broadcast_sink": request.broadcast_sink,
            "decision": decision.decision,
            "reason": _redact(decision.reason),
            "matched_rule_id": decision.matched_rule_id,
            "proxy_name": decision.proxy_name,
            "matched_capability_id": decision.matched_capability_id,
            "reason_code": decision.reason_code,
            "denial_class": decision.denial_class,
        })

    def record_capability_grant(self, capability: Capability) -> None:
        self._entries.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "capability_grant",
            "decision": "grant",
            "reason": capability.constraints.get("planner_reason"),
            "capability_id": capability.capability_id,
            "subject_id": capability.subject_id,
            "action": capability.allowed_action,
            "resource_id": capability.resource_id,
            "resource_label": capability.resource_label,
            "task_id": capability.task_id,
            "tool_name": capability.constraints.get("tool_name"),
            "planner_reason": capability.constraints.get("planner_reason"),
            "max_uses": capability.constraints.get("max_uses"),
        })

    def export_jsonl(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            for entry in self._entries:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def entries(self) -> list[dict[str, Any]]:
        return list(self._entries)


def _redact(text: str) -> str:
    out = text
    for pattern in DEFAULT_SECRET_PATTERNS:
        if pattern in out:
            out = out.replace(pattern, f"{pattern}<redacted>")
    return out
