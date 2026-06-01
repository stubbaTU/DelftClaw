from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from identity.openclaw_identity import OpenClawIdentity
from redteam.primitives.signed_log import SignedAppendOnlyLog


class SQ2SignedAccountabilityLog:
    """SQ2 adapter around the project-wide SignedAppendOnlyLog.

    This keeps SQ2 from creating a second signed-log implementation while
    exposing the compact append/verify/export interface described in SQ2.md.
    """

    def __init__(self, identity: OpenClawIdentity, log_path: str | Path) -> None:
        self.inner = SignedAppendOnlyLog(identity, log_path=str(log_path))
        self.identity = identity

    @property
    def log_path(self) -> str:
        return self.inner.log_path

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        return self.inner.append_event(
            reporter_id=self.identity.identity_hash,
            subject_id=str(event.get("actor_id") or event.get("subject_id") or self.identity.identity_hash),
            action=str(event.get("event_type") or event.get("action") or "sq2_event"),
            severity=int(event.get("severity") or 0),
            details={"event": event},
            evidence={"source": "sq2_signed_accountability_log"},
        )

    def append_event(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.inner.append_event(*args, **kwargs)

    def read_entries(self) -> list[dict[str, Any]]:
        return self.inner.read_entries()

    def verify_chain(self) -> bool:
        return self.inner.verify_integrity()[0]

    def verify_integrity(self) -> tuple[bool, list[str]]:
        return self.inner.verify_integrity()

    def export_jsonl(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            for entry in self.read_entries():
                handle.write(json.dumps(entry, sort_keys=True, default=str) + "\n")

