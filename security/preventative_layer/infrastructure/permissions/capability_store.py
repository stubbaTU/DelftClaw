from __future__ import annotations

from security.preventative_layer.infrastructure.permissions.models import Capability


class CapabilityStore:
    """
    Holds issued capabilities, a revoked set, and a use counter.
    """
    def __init__(self) -> None:
        self._capabilities: dict[str, Capability] = {}
        self._revoked: set[str] = set()
        self._uses: dict[str, int] = {}

    def issue(self, capability: Capability) -> None:
        self._capabilities[capability.capability_id] = capability
        self._revoked.discard(capability.capability_id)
        self._uses.setdefault(capability.capability_id, 0)

    def has_valid_capability(
        self,
        subject_id: str,
        action: str,
        resource_id: str | None = None,
        resource_label: str | None = None,
        task_id: str | None = None,
        current_round: int | None = None,
    ) -> bool:
        return self.find_valid_capability(
            subject_id,
            action,
            resource_id,
            resource_label,
            task_id,
            current_round,
        ) is not None

    def find_valid_capability(
        self,
        subject_id: str,
        action: str,
        resource_id: str | None = None,
        resource_label: str | None = None,
        task_id: str | None = None,
        current_round: int | None = None,
    ) -> Capability | None:
        return next((
            cap
            for cap in self._capabilities.values()
            if self._matches(cap, subject_id, action, resource_id, resource_label, task_id, current_round)
        ), None)

    def consume(self, capability_id: str) -> bool:
        capability = self._capabilities.get(capability_id)
        if capability is None or capability_id in self._revoked:
            return False
        max_uses = capability.constraints.get("max_uses")
        if isinstance(max_uses, int) and self._uses.get(capability_id, 0) >= max_uses:
            return False
        self._uses[capability_id] = self._uses.get(capability_id, 0) + 1
        return True

    def uses(self, capability_id: str) -> int:
        return self._uses.get(capability_id, 0)

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
        max_uses = capability.constraints.get("max_uses")
        if isinstance(max_uses, int) and self._uses.get(capability.capability_id, 0) >= max_uses:
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
