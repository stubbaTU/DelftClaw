from __future__ import annotations

from security.permissions.models import Capability


class CapabilityStore:
    def __init__(self) -> None:
        self._capabilities: dict[str, Capability] = {}
        self._revoked: set[str] = set()

    def issue(self, capability: Capability) -> None:
        self._capabilities[capability.capability_id] = capability
        self._revoked.discard(capability.capability_id)

    def has_valid_capability(
        self,
        subject_id: str,
        action: str,
        resource_id: str | None = None,
        resource_label: str | None = None,
        task_id: str | None = None,
        current_round: int | None = None,
    ) -> bool:
        return any(
            self._matches(cap, subject_id, action, resource_id, resource_label, task_id, current_round)
            for cap in self._capabilities.values()
        )

    def revoke(self, capability_id: str) -> None:
        self._revoked.add(capability_id)

    def revoke_for_subject(self, subject_id: str) -> None:
        for cap in self._capabilities.values():
            if cap.subject_id == subject_id:
                self._revoked.add(cap.capability_id)

    def _matches(
        self,
        capability: Capability,
        subject_id: str,
        action: str,
        resource_id: str | None,
        resource_label: str | None,
        task_id: str | None,
        current_round: int | None,
    ) -> bool:
        if capability.capability_id in self._revoked:
            return False
        if capability.subject_id != subject_id or capability.allowed_action != action:
            return False
        if capability.expires_at_round is not None and current_round is not None:
            if current_round > capability.expires_at_round:
                return False
        if capability.resource_id is not None and capability.resource_id != resource_id:
            return False
        if capability.resource_label is not None and capability.resource_label != resource_label:
            return False
        if capability.task_id is not None and capability.task_id != task_id:
            return False
        return True
