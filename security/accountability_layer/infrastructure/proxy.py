"""
LEGACY
"""
from __future__ import annotations

from typing import Any

from redteam.primitives.signed_log import SignedAppendOnlyLog


class IsolationProxy:
    """Narrow host-side proxy for logging actions from contained code."""

    def __init__(self, agent_id: str, logger: SignedAppendOnlyLog):
        self.agent_id = agent_id
        self.logger = logger

    def log_action(
        self,
        action: str,
        details: dict[str, Any] | None = None,
        *,
        subject_id: str | None = None,
        severity: int = 0,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.logger.append_event(
            reporter_id=self.agent_id,
            subject_id=subject_id or self.agent_id,
            action=action,
            severity=severity,
            details=details or {},
            evidence=evidence,
        )

    def report_violation(
        self,
        action: str,
        details: dict[str, Any] | None = None,
        *,
        subject_id: str | None = None,
        severity: int = 20,
    ) -> dict[str, Any]:
        return self.log_action(action, details, subject_id=subject_id, severity=severity)
