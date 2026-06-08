from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from security.preventative_layer.permissions.effects import EffectClass
from security.preventative_layer.permissions.models import Capability, PermissionRequest, ValidationResult


EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
QUOTED_RE = re.compile(r"['\"]([^'\"]{1,512})['\"]")
DATE_TIME_RE = re.compile(
    r"\b(?:\d{1,2}:\d{2}|\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})\b"
)
IDENTIFIER_KEYS = {
    "address",
    "email",
    "email_address",
    "file_id",
    "id",
    "identifier",
    "recipient",
    "task_id",
    "uid",
    "url",
    "username",
}
IGNORED_EFFECT_KEYS = {
    "action",
    "format",
    "mode",
    "operation",
    "sort",
    "type",
}
STRICT_PROVENANCE_KEYS = {
    "account",
    "address",
    "attachment",
    "body",
    "content",
    "credential",
    "destination",
    "email",
    "file",
    "file_id",
    "file_name",
    "filename",
    "from",
    "host",
    "id",
    "message",
    "participant",
    "participants",
    "path",
    "payload",
    "recipient",
    "recipients",
    "report",
    "target",
    "to",
    "token",
    "url",
}


def normalize(value: Any) -> str:
    return " ".join(str(value).strip().lower().split())


def extract_task_literals(text: str) -> set[str]:
    """Extract exact task values plus task vocabulary for deterministic planning."""

    literals = {normalize(text)}
    for pattern in (EMAIL_RE, URL_RE, QUOTED_RE, DATE_TIME_RE):
        literals.update(normalize(value) for value in pattern.findall(text))
    literals.update(_words(text))
    return {value for value in literals if value}


@dataclass
class ProvenanceStore:
    """Tracks trusted task/identifier values and values observed in content reads."""

    trusted_task_text: str
    trusted_values: set[str] = field(default_factory=set)
    untrusted_values: set[str] = field(default_factory=set)
    observations: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.trusted_values.update(extract_task_literals(self.trusted_task_text))

    def record_read(self, effect_class: EffectClass, result: Any, *, tool_name: str = "") -> None:
        trusted: set[str] = set()
        untrusted: set[str] = set()
        if effect_class is EffectClass.READ_AUTHORITATIVE:
            trusted.update(structured_identifier_values(result))
            untrusted.update(all_string_values(result) - trusted)
        else:
            untrusted.update(all_string_values(result))
        self.trusted_values.update(trusted)
        self.untrusted_values.update(untrusted)
        self.observations.append({
            "tool_name": tool_name,
            "effect_class": effect_class.value,
            "trusted_identifiers": sorted(trusted),
            "untrusted_values": sorted(untrusted),
        })

    def authorize_literal(self, value: Any) -> None:
        normalized = normalize(value)
        if normalized:
            self.trusted_values.add(normalized)

    def is_trusted(self, value: str, capability: Capability | None = None) -> bool:
        candidate = normalize(value)
        if not candidate:
            return True
        authorized = set(self.trusted_values)
        if capability is not None:
            authorized.update(
                normalize(item)
                for item in capability.constraints.get("authorized_literals", [])
                if normalize(item)
            )
        if candidate in authorized:
            return True
        candidate_words = _words(candidate)
        trusted_words = {item for item in authorized if " " not in item}
        return bool(candidate_words) and candidate_words.issubset(trusted_words)

    def untrusted_influence(self, value: str) -> str | None:
        candidate = normalize(value)
        for untrusted in sorted(self.untrusted_values, key=len, reverse=True):
            if len(untrusted) >= 3 and untrusted in candidate:
                return untrusted
        return None


def validate_effect_provenance(
    request: PermissionRequest,
    provenance: ProvenanceStore,
    capabilities: Iterable[Capability],
) -> ValidationResult:
    """Require every security-relevant string argument to have trusted provenance."""

    capability = matching_capability(request, capabilities)
    if capability is None:
        return ValidationResult(False, "no matching task capability for effect")
    for path, value in string_argument_values(request.args):
        if path and path[-1].lower() in IGNORED_EFFECT_KEYS:
            continue
        if provenance.is_trusted(value, capability):
            continue
        influence = provenance.untrusted_influence(value)
        if influence is not None:
            return ValidationResult(False, f"argument {'.'.join(path)} depends on untrusted content")
        if _strict_provenance_path(path):
            return ValidationResult(False, f"argument {'.'.join(path)} has unknown provenance")
    return ValidationResult(True, "effect arguments have trusted provenance")


def matching_capability(request: PermissionRequest, capabilities: Iterable[Capability]) -> Capability | None:
    for capability in capabilities:
        if capability.subject_id != request.subject.subject_id:
            continue
        if capability.allowed_action != request.action:
            continue
        if capability.resource_id is not None and capability.resource_id != request.resource_id:
            continue
        if capability.resource_label is not None and capability.resource_label != request.resource_label:
            continue
        if capability.task_id is not None and capability.task_id != request.task_id:
            continue
        if capability.constraints.get("tool_name") not in {None, request.tool_name}:
            continue
        return capability
    return None


def structured_identifier_values(value: Any, key: str | None = None) -> set[str]:
    values: set[str] = set()
    if hasattr(value, "model_dump"):
        return structured_identifier_values(value.model_dump(), key)
    if isinstance(value, dict):
        for child_key, child in value.items():
            values.update(structured_identifier_values(child, str(child_key).lower()))
        return values
    if isinstance(value, (list, tuple, set)):
        for child in value:
            values.update(structured_identifier_values(child, key))
        return values
    if key and _identifier_key(key) and isinstance(value, (str, int)):
        normalized = normalize(value)
        if normalized:
            values.add(normalized)
    return values


def all_string_values(value: Any) -> set[str]:
    values: set[str] = set()
    if hasattr(value, "model_dump"):
        return all_string_values(value.model_dump())
    if isinstance(value, dict):
        for child in value.values():
            values.update(all_string_values(child))
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            values.update(all_string_values(child))
    elif isinstance(value, str):
        normalized = normalize(value)
        if normalized:
            values.add(normalized)
    return values


def string_argument_values(value: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], str]]:
    values: list[tuple[tuple[str, ...], str]] = []
    if hasattr(value, "model_dump"):
        return string_argument_values(value.model_dump(), path)
    if isinstance(value, dict):
        for key, child in value.items():
            values.extend(string_argument_values(child, (*path, str(key))))
    elif isinstance(value, (list, tuple, set)):
        for index, child in enumerate(value):
            values.extend(string_argument_values(child, (*path, str(index))))
    elif isinstance(value, str) and value.strip():
        values.append((path or ("value",), value))
    return values


def _identifier_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in IDENTIFIER_KEYS or lowered.endswith("_id") or lowered.endswith("_ids")


def _strict_provenance_path(path: tuple[str, ...]) -> bool:
    keys = {part.lower() for part in path if not part.isdigit()}
    return any(
        key in STRICT_PROVENANCE_KEYS
        or key.endswith("_id")
        or key.endswith("_ids")
        or key.endswith("_email")
        or key.endswith("_path")
        or key.endswith("_url")
        for key in keys
    )


def _words(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9@._:+/-]+", normalize(value)))
