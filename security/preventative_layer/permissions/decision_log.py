from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security.preventative_layer.permissions.egress_guard import DEFAULT_SECRET_PATTERNS
from security.preventative_layer.permissions.models import PermissionDecision, PermissionRequest


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
            "decision": decision.decision,
            "reason": _redact(decision.reason),
            "matched_rule_id": decision.matched_rule_id,
            "proxy_name": decision.proxy_name,
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
