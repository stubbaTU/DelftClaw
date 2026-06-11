from __future__ import annotations

import hashlib
from typing import Any

from security.preventative_layer.infrastructure.permissions.models import Subject


class IdentityProxy:
    def __init__(self, key_id: str = "mock_identity_key") -> None:
        self.key_id = key_id

    def sign_nonce(self, subject: Subject, nonce: str) -> dict[str, Any]:
        digest = hashlib.sha256(f"{subject.subject_id}:{nonce}:{self.key_id}".encode("utf-8")).hexdigest()
        return {"ok": True, "key_id": self.key_id, "signature": f"mock_signature_{digest}"}


class WalletProxy:
    def __init__(self, address: str = "tb1q-vukzero-mock", balance_sats: int = 0) -> None:
        self.address = address
        self.balance_sats = balance_sats

    def get_public_wallet_status(self, subject: Subject) -> dict[str, Any]:
        return {"ok": True, "address": self.address, "balance_sats": self.balance_sats}


class AppendOnlyLogProxy:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append_event(self, subject: Subject, event: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        payload = dict(event or kwargs)
        payload["subject_id"] = subject.subject_id
        self.events.append(payload)
        return {"ok": True, "appended": True, "index": len(self.events) - 1}


class ReputationProxy:
    def __init__(self) -> None:
        self.evidence: list[dict[str, Any]] = []
        self.updates: list[dict[str, Any]] = []

    def submit_evidence(self, subject: Subject, event: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        payload = dict(event or kwargs)
        payload["submitted_by"] = subject.subject_id
        self.evidence.append(payload)
        return {"ok": True, "accepted": True}

    def update_reputation_from_engine(self, subject: Subject, update: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        if subject.role != "reputation_engine":
            return {"ok": False, "blocked": True, "reason": "only reputation_engine may mutate scores"}
        payload = dict(update or kwargs)
        self.updates.append(payload)
        return {"ok": True, "updated": True}


class SeedboxProxy:
    def request_seedbox_task(self, subject: Subject, task_id: str, **kwargs: Any) -> dict[str, Any]:
        return {"ok": True, "subject_id": subject.subject_id, "task_id": task_id, "status": "requested"}
