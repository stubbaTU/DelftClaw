from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")


EMAIL_KEYS = {
    "email",
    "email_address",
    "account_email",
    "sender",
    "recipient",
    "recipients",
    "participants",
    "attendees",
    "invitees",
}

FILE_REF_KEYS = {"file_id", "id", "file_name", "filename", "name", "path"}
TEXT_REF_KEYS = {"title", "subject", "summary"}
DANGEROUS_ACTIONS = {"send", "write", "append", "delete", "mutate", "request"}


@dataclass
class AgentDojoRuntimePolicy:
    user_task_text: str
    evidence_emails: set[str] = field(default_factory=set)
    evidence_file_refs: set[str] = field(default_factory=set)
    evidence_text_refs: set[str] = field(default_factory=set)
    denied_dangerous_tools: list[dict[str, Any]] = field(default_factory=list)

    def observe_tool_result(self, tool_name: str, result: Any) -> None:
        if _is_denied_result(result):
            return
        self._observe_value(result)

    def observe_denial(self, tool_name: str, action: str, result: dict[str, Any]) -> None:
        if action in DANGEROUS_ACTIONS:
            self.denied_dangerous_tools.append({
                "tool_name": tool_name,
                "action": action,
                "reason": result.get("reason", ""),
            })

    def has_denied_dangerous_action(self) -> bool:
        return bool(self.denied_dangerous_tools)

    def _observe_value(self, value: Any, key: str | None = None) -> None:
        if value is None:
            return
        if hasattr(value, "model_dump"):
            self._observe_value(value.model_dump())
            return
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                self._observe_value(child_value, str(child_key).lower())
            return
        if isinstance(value, list | tuple | set):
            for item in value:
                self._observe_value(item, key)
            return
        if not isinstance(value, str):
            value = str(value)
        lowered = value.lower()
        if key in EMAIL_KEYS:
            self.evidence_emails.update(EMAIL_RE.findall(value))
        if key in FILE_REF_KEYS and value.strip():
            self.evidence_file_refs.add(lowered)
        if key in TEXT_REF_KEYS and value.strip():
            self.evidence_text_refs.add(lowered)


def _is_denied_result(result: Any) -> bool:
    return isinstance(result, dict) and result.get("error") == "permission_denied"
