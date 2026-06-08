from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Iterable

from security.preventative_layer.permissions.effects import EffectClass
from security.preventative_layer.permissions.models import Capability, PermissionRequest, ValidationResult


EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
QUOTED_RE = re.compile(r"['\"]([^'\"]{1,512})['\"]")
DATE_TIME_RE = re.compile(
    r"\b(?:\d{1,2}:\d{2}|\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4})\b"
)
NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
AMOUNT_RE = re.compile(r"(?:\$\s*(\d+(?:\.\d+)?)|\b(\d+(?:\.\d+)?)\s*(?:usd|eur|gbp|dollars?|euros?|pounds?)\b)", re.I)
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


class Origin(IntEnum):
    """Trust origin. Higher-trust origins take precedence for equal values."""

    UNTRUSTED = 1
    AUTH_READ = 2
    TASK = 3


def normalize(value: Any) -> str:
    return " ".join(str(value).strip().lower().split())


def extract_task_literals(text: str) -> set[str]:
    """Extract strong literals that may authorize effect arguments."""

    literals: set[str] = set()
    for pattern in (EMAIL_RE, URL_RE, QUOTED_RE, DATE_TIME_RE):
        literals.update(normalize(value) for value in pattern.findall(text))
    return {value for value in literals if value}


def extract_task_literals_by_kind(text: str) -> dict[str, set[str]]:
    amounts = {
        _canonical_number(first or second)
        for first, second in AMOUNT_RE.findall(text)
    }
    return {
        "email": {normalize(value) for value in EMAIL_RE.findall(text)},
        "url": {normalize(value) for value in URL_RE.findall(text)},
        "quoted": {normalize(value) for value in QUOTED_RE.findall(text)},
        "date_time": {normalize(value) for value in DATE_TIME_RE.findall(text)},
        "number": {_canonical_number(value) for value in NUMBER_RE.findall(text)},
        "amount": amounts,
    }


def extract_task_vocabulary(text: str) -> set[str]:
    """Extract low-privilege vocabulary usable only to authorize lookup keys."""

    return _words(text)


@dataclass
class ProvenanceStore:
    """Tracks value origins without granting effect authority to loose vocabulary."""

    trusted_task_text: str
    provenance: dict[str, Origin] = field(default_factory=dict)
    task_vocabulary: set[str] = field(default_factory=set)
    observations: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.task_vocabulary.update(extract_task_vocabulary(self.trusted_task_text))
        for value in extract_task_literals(self.trusted_task_text):
            self.observe(value, Origin.TASK)

    @property
    def trusted_values(self) -> set[str]:
        return {value for value, origin in self.provenance.items() if origin >= Origin.AUTH_READ}

    @property
    def untrusted_values(self) -> set[str]:
        return {value for value, origin in self.provenance.items() if origin == Origin.UNTRUSTED}

    @property
    def has_untrusted_observations(self) -> bool:
        return any(origin == Origin.UNTRUSTED for origin in self.provenance.values())

    def observe(self, value: Any, origin: Origin) -> None:
        for candidate in canonical_values(value):
            self.provenance[candidate] = max(origin, self.provenance.get(candidate, origin))

    def record_read(
        self,
        effect_class: EffectClass,
        result: Any,
        *,
        call_args: dict[str, Any] | None = None,
        tool_name: str = "",
        authoritative_lookup_args: tuple[str, ...] | None = None,
    ) -> None:
        args = call_args or {}
        if effect_class is EffectClass.READ_AUTHORITATIVE and args and authoritative_lookup_args is None:
            inputs_trusted = False
            promotion_reason = "authoritative read has arguments but no reviewed authoritative_lookup_args"
        else:
            selected_args = (
                {name: args[name] for name in authoritative_lookup_args if name in args}
                if authoritative_lookup_args is not None
                else args
            )
            missing = set(authoritative_lookup_args or ()) - set(args)
            inputs_trusted = not missing and all(
                self.is_lookup_input_trusted(value)
                for _path, value in primitive_argument_values(selected_args)
            )
            promotion_reason = (
                "reviewed authoritative lookup inputs trusted"
                if inputs_trusted
                else "authoritative lookup inputs missing or untrusted"
            )
        trusted: set[str] = set()
        untrusted: set[str] = set()
        if effect_class is EffectClass.READ_AUTHORITATIVE and inputs_trusted:
            trusted.update(structured_identifier_values(result))
            untrusted.update(all_string_values(result) - trusted)
        else:
            untrusted.update(all_string_values(result))
        for value in trusted:
            self.observe(value, Origin.AUTH_READ)
        for value in untrusted:
            self.observe(value, Origin.UNTRUSTED)
        self.observations.append({
            "tool_name": tool_name,
            "effect_class": effect_class.value,
            "lookup_inputs_trusted": inputs_trusted,
            "promotion_reason": promotion_reason,
            "authoritative_lookup_args": list(authoritative_lookup_args or ()),
            "trusted_identifiers": sorted(trusted),
            "untrusted_values": sorted(untrusted),
        })

    def authorize_literal(self, value: Any) -> None:
        self.observe(value, Origin.TASK)

    def is_lookup_input_trusted(self, value: Any) -> bool:
        if self.is_trusted(value):
            return True
        candidate_words = _words(str(value))
        return bool(candidate_words) and candidate_words.issubset(self.task_vocabulary)

    def is_trusted(self, value: Any, capability: Capability | None = None) -> bool:
        candidates = canonical_values(value)
        if not candidates:
            return True
        if any(self.provenance.get(candidate, Origin.UNTRUSTED) >= Origin.AUTH_READ for candidate in candidates):
            return True
        if capability is None:
            return False
        authorized = {
            candidate
            for item in capability.constraints.get("authorized_literals", [])
            for candidate in canonical_values(item)
        }
        return bool(candidates.intersection(authorized))

    def untrusted_influence(self, value: Any) -> str | None:
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
    """Require trusted provenance for every effect argument by default."""

    capability = matching_capability(request, capabilities)
    if capability is None:
        return ValidationResult(
            False,
            "no matching task capability for effect",
            reason_code="capability_mismatch",
            denial_class="security_enforcement",
        )
    neutral_args = set(request.neutral_args)
    if request.broadcast_sink and provenance.has_untrusted_observations and not request.allow_content_after_untrusted:
        if any(name not in neutral_args for name in request.args):
            return ValidationResult(
                False,
                "broadcast/public effect denied after untrusted read",
                reason_code="broadcast_after_untrusted_read",
                denial_class="utility_ceiling",
            )
    for path, value in primitive_argument_values(request.args):
        top_level = path[0] if path else "value"
        if top_level in neutral_args:
            if provenance.untrusted_influence(value) is not None:
                return ValidationResult(
                    False,
                    f"neutral argument {'.'.join(path)} depends on untrusted content",
                    reason_code="untrusted_neutral_argument",
                    denial_class="security_enforcement",
                )
            continue
        bound_literals = set(capability.constraints.get("argument_literals", {}).get(top_level, ()))
        if bound_literals:
            if canonical_values(value).intersection(bound_literals):
                continue
            return ValidationResult(
                False,
                f"argument {'.'.join(path)} does not match its capability-bound task literal",
                reason_code="capability_argument_mismatch",
                denial_class="security_enforcement",
            )
        if provenance.is_trusted(value, capability):
            continue
        influence = provenance.untrusted_influence(value)
        if influence is not None:
            return ValidationResult(
                False,
                f"argument {'.'.join(path)} depends on untrusted content",
                reason_code="untrusted_argument_influence",
                denial_class="security_enforcement",
            )
        return ValidationResult(
            False,
            f"argument {'.'.join(path)} has no trusted provenance",
            reason_code="unknown_argument_provenance",
            denial_class="utility_ceiling",
        )
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
        values.update(canonical_values(value))
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
        values.update(canonical_values(value))
    return values


def primitive_argument_values(value: Any, path: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    values: list[tuple[tuple[str, ...], Any]] = []
    if hasattr(value, "model_dump"):
        return primitive_argument_values(value.model_dump(), path)
    if isinstance(value, dict):
        for key, child in value.items():
            values.extend(primitive_argument_values(child, (*path, str(key))))
    elif isinstance(value, (list, tuple, set)):
        for index, child in enumerate(value):
            values.extend(primitive_argument_values(child, (*path, str(index))))
    elif value is not None:
        values.append((path or ("value",), value))
    return values


def canonical_values(value: Any) -> set[str]:
    normalized = normalize(value)
    if not normalized:
        return set()
    values = {normalized}
    number = _canonical_number(value)
    if number:
        values.add(number)
    for address in EMAIL_RE.findall(str(value)):
        local, domain = address.lower().rsplit("@", 1)
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            pass
        values.add(f"{local}@{domain}")
    return values


def _canonical_number(value: Any) -> str:
    match = re.fullmatch(r"\s*\$?\s*(\d+(?:\.\d+)?)\s*(?:[A-Za-z]{3})?\s*", str(value))
    if not match:
        return ""
    try:
        number = Decimal(match.group(1)).normalize()
    except InvalidOperation:
        return ""
    return f"number:{format(number, 'f')}"


def _identifier_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in IDENTIFIER_KEYS or lowered.endswith("_id") or lowered.endswith("_ids")


def _words(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9@._:+/-]+", normalize(value)))
