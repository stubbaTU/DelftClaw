from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


DecisionEffect = Literal["allow", "deny", "allow_via_proxy"]


@dataclass(frozen=True)
class Subject:
    subject_id: str
    role: str


@dataclass(frozen=True)
class Resource:
    resource_id: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Capability:
    capability_id: str
    subject_id: str
    allowed_action: str
    resource_id: str | None = None
    resource_label: str | None = None
    task_id: str | None = None
    expires_at_round: int | None = None
    constraints: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PermissionRequest:
    request_id: str
    subject: Subject
    tool_name: str
    action: str
    resource_id: str | None
    resource_label: str | None
    args: dict[str, Any]
    task_id: str | None = None
    sink: str | None = None
    input_taint: str | None = None
    effect_class: str | None = None
    classification_source: str | None = None


@dataclass(frozen=True)
class PermissionDecision:
    request_id: str
    decision: DecisionEffect
    reason: str
    matched_rule_id: str | None = None
    proxy_name: str | None = None
    sanitized_args: dict[str, Any] | None = None


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    reason: str
    sanitized_args: dict[str, Any] | None = None


@dataclass(frozen=True)
class PolicyRule:
    id: str
    role: str
    action: str
    effect: DecisionEffect
    resource_label: str | None = None
    resource_id: str | None = None
    proxy: str | None = None
    requires_capability: bool = False
    validators: tuple[str, ...] = ()


@dataclass(frozen=True)
class Policy:
    version: int
    default_effect: Literal["deny"]
    roles: dict[str, dict[str, Any]]
    resource_labels: dict[str, dict[str, Any]]
    rules: tuple[PolicyRule, ...]
