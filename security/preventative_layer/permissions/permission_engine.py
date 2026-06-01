from __future__ import annotations

from dataclasses import replace

from security.preventative_layer.permissions.capability_store import CapabilityStore
from security.preventative_layer.permissions.decision_log import DecisionLog
from security.preventative_layer.permissions.models import PermissionDecision, PermissionRequest, Policy, PolicyRule
from security.preventative_layer.permissions.resource_registry import ResourceRegistry
from security.preventative_layer.permissions.validators import ValidatorRegistry


class PermissionEngine:
    def __init__(
        self,
        policy: Policy,
        resource_registry: ResourceRegistry,
        capability_store: CapabilityStore,
        validator_registry: ValidatorRegistry,
        decision_log: DecisionLog,
    ) -> None:
        self.policy = policy
        self.resource_registry = resource_registry
        self.capability_store = capability_store
        self.validator_registry = validator_registry
        self.decision_log = decision_log

    def decide(
        self,
        request: PermissionRequest,
        current_round: int | None = None,
    ) -> PermissionDecision:
        decision = self._decide(request, current_round=current_round)
        self.decision_log.record(request, decision)
        return decision

    def _decide(self, request: PermissionRequest, current_round: int | None) -> PermissionDecision:
        resource_label = request.resource_label
        if request.resource_id:
            resource = self.resource_registry.resolve(request.resource_id)
            if resource is None:
                return _deny(request, "unknown resource")
            resource_label = resource.label
            request = replace(request, resource_label=resource_label)
        if not resource_label:
            return _deny(request, "resource label could not be resolved")

        matches = [
            rule for rule in self.policy.rules
            if _rule_matches(rule, request, resource_label)
        ]
        if not matches:
            return _deny(request, "no matching allow rule")

        deny_rule = next((rule for rule in matches if rule.effect == "deny"), None)
        if deny_rule is not None:
            return _deny(request, f"denied by policy rule {deny_rule.id}", deny_rule.id)

        exact = [rule for rule in matches if rule.resource_id is not None and rule.resource_id == request.resource_id]
        allow_rule = (exact or matches)[0]

        if allow_rule.requires_capability:
            ok = self.capability_store.has_valid_capability(
                request.subject.subject_id,
                request.action,
                resource_id=request.resource_id,
                resource_label=resource_label,
                task_id=request.task_id,
                current_round=current_round,
            )
            if not ok:
                return _deny(request, "missing or expired capability", allow_rule.id)

        sanitized_args = request.args
        for validator_name in allow_rule.validators:
            result = self.validator_registry.run(validator_name, replace(request, args=sanitized_args))
            if not result.ok:
                return _deny(request, f"{validator_name} failed: {result.reason}", allow_rule.id)
            if result.sanitized_args is not None:
                sanitized_args = result.sanitized_args

        return PermissionDecision(
            request_id=request.request_id,
            decision=allow_rule.effect,
            reason=f"allowed by policy rule {allow_rule.id}",
            matched_rule_id=allow_rule.id,
            proxy_name=allow_rule.proxy,
            sanitized_args=sanitized_args,
        )


def _rule_matches(rule: PolicyRule, request: PermissionRequest, resource_label: str) -> bool:
    if rule.role != request.subject.role or rule.action != request.action:
        return False
    if rule.resource_id is not None:
        return rule.resource_id == request.resource_id
    return rule.resource_label == resource_label


def _deny(request: PermissionRequest, reason: str, rule_id: str | None = None) -> PermissionDecision:
    return PermissionDecision(
        request_id=request.request_id,
        decision="deny",
        reason=reason,
        matched_rule_id=rule_id,
    )
