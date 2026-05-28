from __future__ import annotations

import json
from typing import Any

from security.permissions.egress_guard import EgressGuard
from security.permissions.models import Capability, PermissionRequest, ValidationResult
from security.permissions.validators import ValidatorRegistry, default_validator_registry
from security.agentdojo_vukzero.runtime_policy import AgentDojoRuntimePolicy


def build_agentdojo_validator_registry(
    capabilities: list[Capability],
    egress_guard: EgressGuard | None = None,
    runtime_policy: AgentDojoRuntimePolicy | None = None,
) -> ValidatorRegistry:
    registry = default_validator_registry(egress_guard)
    guard = egress_guard or EgressGuard()
    registry.register("agentdojo_send_email_capability", lambda request: _validate_email(request, capabilities, runtime_policy))
    registry.register("agentdojo_file_share_capability", lambda request: _validate_file_share(request, capabilities, runtime_policy))
    registry.register("agentdojo_calendar_capability", lambda request: _validate_calendar(request, capabilities, runtime_policy))
    registry.register("agentdojo_file_mutation_capability", lambda request: _validate_file_mutation(request, capabilities, runtime_policy))
    registry.register("agentdojo_external_sink_egress", lambda request: guard.check_payload(request.args))
    registry.register("agentdojo_capability_constraints", lambda request: _validate_generic_constraints(request, capabilities, runtime_policy))
    return registry


def _matching_capability(request: PermissionRequest, capabilities: list[Capability]) -> Capability | None:
    for cap in capabilities:
        if cap.subject_id != request.subject.subject_id:
            continue
        if cap.allowed_action != request.action:
            continue
        if cap.resource_id is not None and cap.resource_id != request.resource_id:
            continue
        if cap.task_id is not None and cap.task_id != request.task_id:
            continue
        if cap.constraints.get("tool_name") not in {None, request.tool_name}:
            continue
        return cap
    return None


def _validate_email(
    request: PermissionRequest,
    capabilities: list[Capability],
    runtime_policy: AgentDojoRuntimePolicy | None = None,
) -> ValidationResult:
    cap = _matching_capability(request, capabilities)
    if cap is None:
        return ValidationResult(False, "no matching email capability")
    allowed = set(cap.constraints.get("allowed_recipients", []))
    if runtime_policy is not None:
        allowed.update(runtime_policy.evidence_emails)
    actual = _collect_recipients(request.args)
    if allowed and not actual.issubset(allowed):
        return ValidationResult(False, "recipient not authorized by user task capability")
    if actual and cap.constraints.get("requires_authorized_recipients") and not allowed:
        return ValidationResult(False, "recipient requires trusted task evidence")
    if not actual:
        return ValidationResult(False, "email tool call has no recipient")
    return _contains_required_text(request, cap)


def _validate_file_share(
    request: PermissionRequest,
    capabilities: list[Capability],
    runtime_policy: AgentDojoRuntimePolicy | None = None,
) -> ValidationResult:
    cap = _matching_capability(request, capabilities)
    if cap is None:
        return ValidationResult(False, "no matching file-share capability")
    allowed_recipients = set(cap.constraints.get("allowed_recipients", []))
    if runtime_policy is not None:
        allowed_recipients.update(runtime_policy.evidence_emails)
    actual_recipients = _collect_recipients(request.args)
    if allowed_recipients and not actual_recipients.issubset(allowed_recipients):
        return ValidationResult(False, "file-share recipient not authorized")
    if actual_recipients and cap.constraints.get("requires_authorized_recipients") and not allowed_recipients:
        return ValidationResult(False, "file-share recipient requires trusted task evidence")
    allowed_refs = {str(value).lower() for value in cap.constraints.get("allowed_file_refs", [])}
    if runtime_policy is not None:
        allowed_refs.update(runtime_policy.evidence_file_refs)
    if allowed_refs:
        actual_ref = _first_present(request.args, ("file_id", "file_name", "filename", "name", "path"))
        if actual_ref is None or all(ref not in str(actual_ref).lower() for ref in allowed_refs):
            return ValidationResult(False, "file reference not authorized")
    elif cap.constraints.get("requires_authorized_file_ref") and _first_present(
        request.args, ("file_id", "file_name", "filename", "name", "path")
    ) is not None:
        return ValidationResult(False, "file reference requires trusted task evidence")
    return ValidationResult(True, "file-share capability accepted")


def _validate_calendar(
    request: PermissionRequest,
    capabilities: list[Capability],
    runtime_policy: AgentDojoRuntimePolicy | None = None,
) -> ValidationResult:
    cap = _matching_capability(request, capabilities)
    if cap is None:
        return ValidationResult(False, "no matching calendar capability")
    allowed = set(cap.constraints.get("allowed_participants", []))
    if runtime_policy is not None:
        allowed.update(runtime_policy.evidence_emails)
    actual = _collect_values(request.args, ("participants", "attendees", "invitees", "emails"))
    if allowed and actual and not actual.issubset(allowed):
        return ValidationResult(False, "calendar participant not authorized")
    if actual and cap.constraints.get("requires_authorized_recipients") and not allowed:
        return ValidationResult(False, "calendar participant requires trusted task evidence")
    return ValidationResult(True, "calendar capability accepted")


def _validate_file_mutation(
    request: PermissionRequest,
    capabilities: list[Capability],
    runtime_policy: AgentDojoRuntimePolicy | None = None,
) -> ValidationResult:
    cap = _matching_capability(request, capabilities)
    if cap is None:
        return ValidationResult(False, "no matching file mutation capability")
    allowed_refs = {str(value).lower() for value in cap.constraints.get("allowed_file_refs", [])}
    if runtime_policy is not None:
        allowed_refs.update(runtime_policy.evidence_file_refs)
    if allowed_refs:
        actual_ref = _first_present(request.args, ("file_id", "file_name", "filename", "name", "path"))
        if actual_ref is None or all(ref not in str(actual_ref).lower() for ref in allowed_refs):
            return ValidationResult(False, "file mutation target not authorized")
    elif cap.constraints.get("requires_authorized_file_ref") and _first_present(
        request.args, ("file_id", "file_name", "filename", "name", "path")
    ) is not None:
        return ValidationResult(False, "file mutation target requires trusted task evidence")
    return ValidationResult(True, "file mutation capability accepted")


def _validate_generic_constraints(
    request: PermissionRequest,
    capabilities: list[Capability],
    runtime_policy: AgentDojoRuntimePolicy | None = None,
) -> ValidationResult:
    if request.tool_name == "send_email":
        return _validate_email(request, capabilities, runtime_policy)
    if request.tool_name == "share_file":
        return _validate_file_share(request, capabilities, runtime_policy)
    if request.tool_name in {"create_calendar_event", "cancel_calendar_event", "reschedule_calendar_event", "add_calendar_event_participants"}:
        return _validate_calendar(request, capabilities, runtime_policy)
    if request.tool_name in {"create_file", "append_to_file", "delete_file"}:
        return _validate_file_mutation(request, capabilities, runtime_policy)
    if _matching_capability(request, capabilities) is None:
        return ValidationResult(False, "no matching AgentDojo capability")
    return ValidationResult(True, "AgentDojo capability accepted")


def _contains_required_text(request: PermissionRequest, cap: Capability) -> ValidationResult:
    required = [str(value).lower() for value in cap.constraints.get("allowed_subject_or_body_contains", [])]
    if not required:
        return ValidationResult(True, "email capability accepted")
    haystack = json.dumps(request.args, default=str).lower()
    if any(value.lower() in haystack for value in required):
        return ValidationResult(True, "email capability accepted")
    return ValidationResult(False, "email subject/body not authorized by user task capability")


def _collect_recipients(args: dict[str, Any]) -> set[str]:
    return _collect_values(args, ("recipient", "recipients", "to", "to_email", "email", "cc", "bcc"))


def _collect_values(args: dict[str, Any], keys: tuple[str, ...]) -> set[str]:
    values: set[str] = set()
    for key in keys:
        value = args.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            values.add(value)
        elif isinstance(value, list | tuple | set):
            values.update(str(item) for item in value)
    return values


def _first_present(args: dict[str, Any], keys: tuple[str, ...]) -> Any | None:
    for key in keys:
        if args.get(key) is not None:
            return args[key]
    return None
