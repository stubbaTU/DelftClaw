from __future__ import annotations

from typing import Any, Protocol


class CommunityAuditLog(Protocol):
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
        ...


class CommunityCommunicationPort(Protocol):
    def send_message(self, *, sender_id: str, recipient_id: str, message: str) -> dict[str, Any]:
        ...

    def broadcast(self, *, sender_id: str, community_id: str, message: str) -> dict[str, Any]:
        ...

    def request_file_location(self, *, sender_id: str, community_id: str, query: str) -> dict[str, Any]:
        ...


class NullCommunityAuditLog:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

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
        event = {
            "actor_id": actor_id,
            "subject_id": subject_id,
            "action": action,
            "details": details,
            "severity": severity,
            "evidence": evidence or {},
        }
        self.events.append(event)
        return event


class LocalCommunicationPlaceholder:
    """Placeholder until the real inter-agent communication layer is merged."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    def send_message(self, *, sender_id: str, recipient_id: str, message: str) -> dict[str, Any]:
        record = {
            "todo": "replace with teammate communication adapter",
            "type": "send_message",
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "message": message,
        }
        self.messages.append(record)
        return {"ok": True, **record}

    def broadcast(self, *, sender_id: str, community_id: str, message: str) -> dict[str, Any]:
        record = {
            "todo": "replace with teammate communication adapter",
            "type": "broadcast",
            "sender_id": sender_id,
            "community_id": community_id,
            "message": message,
        }
        self.messages.append(record)
        return {"ok": True, **record}

    def request_file_location(self, *, sender_id: str, community_id: str, query: str) -> dict[str, Any]:
        record = {
            "todo": "replace with teammate communication adapter",
            "type": "request_file_location",
            "sender_id": sender_id,
            "community_id": community_id,
            "query": query,
        }
        self.messages.append(record)
        return {"ok": True, **record}
