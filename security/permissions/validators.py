from __future__ import annotations

import json
import re
from dataclasses import replace
from typing import Any, Callable

from security.permissions.egress_guard import EgressGuard
from security.permissions.models import PermissionRequest, ValidationResult


ValidatorFn = Callable[[PermissionRequest], ValidationResult]


class ValidatorRegistry:
    def __init__(self) -> None:
        self._validators: dict[str, ValidatorFn] = {}

    def register(self, name: str, fn: ValidatorFn) -> None:
        self._validators[name] = fn

    def names(self) -> set[str]:
        return set(self._validators)

    def run(self, name: str, request: PermissionRequest) -> ValidationResult:
        fn = self._validators.get(name)
        if fn is None:
            return ValidationResult(False, f"unknown validator {name}")
        try:
            return fn(request)
        except Exception as exc:
            return ValidationResult(False, f"validator {name} failed closed: {type(exc).__name__}")


def default_validator_registry(egress_guard: EgressGuard | None = None) -> ValidatorRegistry:
    guard = egress_guard or EgressGuard()
    registry = ValidatorRegistry()
    registry.register("nonce_only", nonce_only)
    registry.register("bounded_log_event_schema", bounded_log_event_schema)
    registry.register("peer_message_schema", peer_message_schema)
    registry.register("report_schema", report_schema)
    registry.register("reputation_update_schema", reputation_update_schema)
    registry.register("seedbox_request_schema", seedbox_request_schema)
    registry.register("egress_no_secret_canary", lambda request: guard.check_payload(request.args))
    registry.register("no_raw_secret_resource", no_raw_secret_resource)
    registry.register("no_path_traversal", no_path_traversal)
    registry.register("max_payload_size", max_payload_size)
    registry.register("allowed_event_type", allowed_event_type)
    return registry


def nonce_only(request: PermissionRequest) -> ValidationResult:
    if set(request.args) != {"nonce"}:
        return ValidationResult(False, "nonce_only requires exactly nonce")
    nonce = request.args.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return ValidationResult(False, "nonce must be a non-empty string")
    if len(nonce) > 256:
        return ValidationResult(False, "nonce is too large")
    if _contains_instruction_or_secret(nonce):
        return ValidationResult(False, "nonce contains forbidden content")
    return ValidationResult(True, "nonce accepted")


def bounded_log_event_schema(request: PermissionRequest) -> ValidationResult:
    event = request.args.get("event") if "event" in request.args else request.args
    if not isinstance(event, dict):
        return ValidationResult(False, "log event must be an object")
    if any(key in event for key in ("rewrite", "delete", "truncate", "raw_log")):
        return ValidationResult(False, "log event attempts forbidden log mutation")
    event_type = event.get("event_type") or event.get("action")
    if not isinstance(event_type, str) or not event_type:
        return ValidationResult(False, "log event requires event_type or action")
    if _payload_size(event) > 8192:
        return ValidationResult(False, "log event is too large")
    return ValidationResult(True, "log event accepted")


def peer_message_schema(request: PermissionRequest) -> ValidationResult:
    message = request.args.get("message")
    recipient = request.args.get("recipient", "peer")
    if not isinstance(message, str):
        return ValidationResult(False, "peer message requires string message")
    if not isinstance(recipient, str) or not recipient:
        return ValidationResult(False, "peer message requires recipient")
    if len(message) > 4096:
        return ValidationResult(False, "peer message is too large")
    forbidden = {"private_identity_key", "wallet_seed", "raw_secret"}
    if forbidden & set(request.args):
        return ValidationResult(False, "peer message contains forbidden fields")
    return ValidationResult(True, "peer message accepted")


def report_schema(request: PermissionRequest) -> ValidationResult:
    report = request.args.get("report", request.args.get("payload", request.args))
    if _payload_size(report) > 8192:
        return ValidationResult(False, "report is too large")
    return ValidationResult(True, "report accepted")


def reputation_update_schema(request: PermissionRequest) -> ValidationResult:
    if not isinstance(request.args, dict):
        return ValidationResult(False, "reputation update must be an object")
    if "subject_id" not in request.args and "event" not in request.args:
        return ValidationResult(False, "reputation update requires subject_id or event")
    return ValidationResult(True, "reputation update accepted")


def seedbox_request_schema(request: PermissionRequest) -> ValidationResult:
    task_id = request.args.get("task_id") or request.task_id
    if not isinstance(task_id, str) or not task_id:
        return ValidationResult(False, "seedbox request requires task_id")
    if _payload_size(request.args) > 4096:
        return ValidationResult(False, "seedbox request is too large")
    return ValidationResult(True, "seedbox request accepted")


def no_raw_secret_resource(request: PermissionRequest) -> ValidationResult:
    if request.resource_label and request.resource_label.startswith("secret."):
        return ValidationResult(False, "raw secret resource access is forbidden")
    return ValidationResult(True, "resource is not raw secret")


def no_path_traversal(request: PermissionRequest) -> ValidationResult:
    for key in ("path", "file_path", "target_path"):
        value = request.args.get(key)
        if not isinstance(value, str):
            continue
        normalized = value.replace("\\", "/")
        if "../" in normalized or normalized.startswith("../") or "/.." in normalized:
            return ValidationResult(False, "path traversal is forbidden")
    return ValidationResult(True, "paths accepted")


def max_payload_size(request: PermissionRequest) -> ValidationResult:
    if _payload_size(request.args) > 8192:
        return ValidationResult(False, "payload is too large")
    return ValidationResult(True, "payload size accepted")


def allowed_event_type(request: PermissionRequest) -> ValidationResult:
    event_type = request.args.get("event_type") or request.args.get("action")
    if event_type is None:
        return ValidationResult(True, "no event type provided")
    allowed = {
        "microtask_report",
        "microtask_verified",
        "security_report",
        "donation_broadcast",
        "peer_endorsement",
        "reputation_update",
        "policy_violation",
        "expulsion_decision",
    }
    if event_type not in allowed:
        return ValidationResult(False, f"event type {event_type!r} is not allowed")
    return ValidationResult(True, "event type accepted")


def _contains_instruction_or_secret(text: str) -> bool:
    lowered = text.lower()
    if any(term in lowered for term in ("ignore previous", "private key", "wallet seed", "exfiltrate")):
        return True
    return "CANARY_" in text


def _payload_size(value: Any) -> int:
    return len(json.dumps(value, default=str, sort_keys=True))
