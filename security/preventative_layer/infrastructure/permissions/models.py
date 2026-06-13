from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


DecisionEffect = Literal["allow", "deny", "allow_via_proxy"]


@dataclass(frozen=True)
class Subject:
    """
    Who is acting and in what role (the role is what policy rules match on e.g normal agent.)
    """
    subject_id: str
    role: str


@dataclass(frozen=True)
class Resource:
    """
    Thing that the subject is acting on (wallet, message...).
    """
    resource_id: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Capability:
    """
    Dataclass saying "this subject may do this action on this resource for this task", with optional constraints and expiration.
    """
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
    """
    Dataclass representing a permission request for a tool-call: provides everything the permission engine needs to decide.
    """
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
    neutral_args: tuple[str, ...] = ()
    broadcast_sink: bool = False
    allow_content_after_untrusted: bool = False


@dataclass(frozen=True)
class PermissionDecision:
    """
    Verdict of permission request: allow, deny, or allow_via_proxy with accompanying reason and metadata.
    """
    request_id: str
    decision: DecisionEffect
    reason: str
    matched_rule_id: str | None = None
    proxy_name: str | None = None
    sanitized_args: dict[str, Any] | None = None
    matched_capability_id: str | None = None
    reason_code: str | None = None
    denial_class: str | None = None


@dataclass(frozen=True)
class ValidationResult:
    """
    Validation of arguments through checking provenance.
    """
    ok: bool
    reason: str
    sanitized_args: dict[str, Any] | None = None
    reason_code: str | None = None
    denial_class: str | None = None


@dataclass(frozen=True)
class PolicyRule:
    """
    A single allow/deny rule of a tool call
    """
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
    """
    Full set of policy rules for a tool call.
    """
    version: int
    default_effect: Literal["deny"]
    roles: dict[str, dict[str, Any]]
    resource_labels: dict[str, dict[str, Any]]
    rules: tuple[PolicyRule, ...]
