from __future__ import annotations

from dataclasses import replace

from security.preventative_layer.infrastructure.permissions.capability_store import CapabilityStore
from security.preventative_layer.infrastructure.permissions.decision_log import DecisionLog
from security.preventative_layer.infrastructure.permissions.models import PermissionDecision, PermissionRequest, Policy, PolicyRule
from security.preventative_layer.infrastructure.permissions.resource_registry import ResourceRegistry
from security.preventative_layer.infrastructure.permissions.validators import ValidatorRegistry


class PermissionEngine:
    """
    Reference monitor that decides whether a request is allowed or denied.
    It resolves resources, finds matching rules, looks for capabilities, runs validators, and applies proxies.
    """
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
                return _deny(request, "unknown resource", reason_code="unknown_resource")
            resource_label = resource.label
            request = replace(request, resource_label=resource_label)
        if not resource_label:
            return _deny(request, "resource label could not be resolved", reason_code="unresolved_resource")

        matches = [
            rule for rule in self.policy.rules
            if _rule_matches(rule, request, resource_label)
        ]
        if not matches:
            return _deny(request, "no matching allow rule", reason_code="policy_no_allow_rule")

        deny_rule = next((rule for rule in matches if rule.effect == "deny"), None)
        if deny_rule is not None:
            return _deny(
                request,
                f"denied by policy rule {deny_rule.id}",
                deny_rule.id,
                reason_code="policy_explicit_deny",
            )

        exact = [rule for rule in matches if rule.resource_id is not None and rule.resource_id == request.resource_id]
        allow_rule = (exact or matches)[0]

        matched_capability = None
        if allow_rule.requires_capability:
            matched_capability = self.capability_store.find_valid_capability(
                request.subject.subject_id,
                request.action,
                resource_id=request.resource_id,
                resource_label=resource_label,
                task_id=request.task_id,
                current_round=current_round,
            )
            if matched_capability is None:
                return _deny(
                    request,
                    "missing or expired capability, or capability use limit exhausted",
                    allow_rule.id,
                    reason_code="capability_unavailable",
                )

        sanitized_args = request.args
        for validator_name in allow_rule.validators:
            result = self.validator_registry.run(validator_name, replace(request, args=sanitized_args))
            if not result.ok:
                return _deny(
                    request,
                    f"{validator_name} failed: {result.reason}",
                    allow_rule.id,
                    reason_code=result.reason_code or f"validator_{validator_name}",
                    denial_class=result.denial_class or "security_enforcement",
                )
            if result.sanitized_args is not None:
                sanitized_args = result.sanitized_args

        return PermissionDecision(
            request_id=request.request_id,
            decision=allow_rule.effect,
            reason=f"allowed by policy rule {allow_rule.id}",
            matched_rule_id=allow_rule.id,
            proxy_name=allow_rule.proxy,
            sanitized_args=sanitized_args,
            matched_capability_id=matched_capability.capability_id if matched_capability else None,
        )


def _rule_matches(rule: PolicyRule, request: PermissionRequest, resource_label: str) -> bool:
    if rule.role != request.subject.role or rule.action != request.action:
        return False
    if rule.resource_id is not None:
        return rule.resource_id == request.resource_id
    return rule.resource_label == resource_label


def _deny(
    request: PermissionRequest,
    reason: str,
    rule_id: str | None = None,
    *,
    reason_code: str = "security_denial",
    denial_class: str = "security_enforcement",
) -> PermissionDecision:
    return PermissionDecision(
        request_id=request.request_id,
        decision="deny",
        reason=reason,
        matched_rule_id=rule_id,
        reason_code=reason_code,
        denial_class=denial_class,
    )
