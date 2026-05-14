from __future__ import annotations

from pathlib import Path
from typing import Any

from identity.openclaw_identity import OpenClawIdentity
from redteam.primitives.signed_log import SignedAppendOnlyLog


class SignedCommunityAuditLog:
    """Security-owned adapter that records community events into signed logs."""

    def __init__(
        self,
        *,
        log_path: str | Path,
        identity: OpenClawIdentity,
        reporter_id: str | None = None,
    ) -> None:
        self.log = SignedAppendOnlyLog(identity, log_path=log_path)
        self.reporter_id = reporter_id or identity.public_bundle()["agent_id"]

    def record(
        self,
        *,
        actor_id: str,
        subject_id: str,
        action: str,
        details: dict[str, Any],
        severity: int = 0,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = {"actor_id": actor_id, **details}
        return self.log.append_event(
            reporter_id=self.reporter_id,
            subject_id=subject_id,
            action=action,
            severity=severity,
            details=payload,
            evidence=evidence,
        )
