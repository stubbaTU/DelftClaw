from __future__ import annotations

import inspect
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class EffectClass(str, Enum):
    """Security-relevant behavior of a tool."""

    READ_AUTHORITATIVE = "read_authoritative"
    READ_CONTENT = "read_content"
    EFFECT = "effect"


@dataclass(frozen=True)
class ToolSecuritySpec:
    """Trusted metadata used to classify and authorize a tool."""

    name: str
    description: str = ""
    parameters: Mapping[str, Any] = field(default_factory=dict)
    annotations: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolClassification:
    name: str
    effect_class: EffectClass
    action: str
    resource_id: str
    resource_label: str
    requires_capability: bool
    sink: str | None = None
    classification_source: str = "inferred"
    neutral_args: tuple[str, ...] = ()
    broadcast_sink: bool = False
    allow_content_after_untrusted: bool = False
    authoritative_lookup_args: tuple[str, ...] | None = None


READ_PREFIXES = {
    "check",
    "describe",
    "find",
    "get",
    "inspect",
    "list",
    "load",
    "lookup",
    "query",
    "read",
    "search",
    "show",
    "stat",
    "view",
}
EFFECT_PREFIXES = {
    "add",
    "append",
    "apply",
    "book",
    "broadcast",
    "cancel",
    "create",
    "delete",
    "donate",
    "execute",
    "grant",
    "invoke",
    "join",
    "modify",
    "move",
    "mutate",
    "pay",
    "post",
    "publish",
    "remove",
    "request",
    "reschedule",
    "rewrite",
    "seed",
    "send",
    "set",
    "share",
    "sign",
    "submit",
    "transfer",
    "truncate",
    "update",
    "upload",
    "write",
}
SENSITIVE_TERMS = {
    "credential",
    "identity",
    "key",
    "password",
    "private",
    "secret",
    "seed",
    "token",
    "wallet",
}
def classify_tool(spec: ToolSecuritySpec) -> ToolClassification:
    """Classify a tool from trusted metadata, failing ambiguous cases closed."""

    explicit = _explicit_effect(spec.annotations)
    if explicit is not None:
        if explicit is EffectClass.READ_AUTHORITATIVE and spec.annotations.get("mutable_source") is True:
            return _classification(
                spec.name,
                EffectClass.READ_CONTENT,
                source="mutable-source",
                annotations=spec.annotations,
            )
        return _classification(spec.name, explicit, source="annotation", annotations=spec.annotations)

    tokens = set(_tokens(f"{spec.name} {spec.description}"))
    first = _tokens(spec.name)
    first_token = first[0] if first else ""

    if tokens & SENSITIVE_TERMS:
        return _classification(spec.name, EffectClass.EFFECT, source="sensitive-default", annotations=spec.annotations)
    if first_token in EFFECT_PREFIXES:
        return _classification(spec.name, EffectClass.EFFECT, source="effect-verb", annotations=spec.annotations)
    if first_token in READ_PREFIXES:
        return _classification(
            spec.name,
            EffectClass.READ_CONTENT,
            source="read-default-untrusted",
            annotations=spec.annotations,
        )
    return _classification(spec.name, EffectClass.EFFECT, source="ambiguous-default", annotations=spec.annotations)


def tool_security_spec(
    tool: Any,
    *,
    fallback_name: str | None = None,
    annotation_overrides: Mapping[str, Any] | None = None,
) -> ToolSecuritySpec:
    """Extract security metadata from common OpenAI/MCP/tool wrapper shapes."""

    name = str(getattr(tool, "name", fallback_name or "") or fallback_name or "")
    description = str(getattr(tool, "description", "") or "")
    parameters = getattr(tool, "parameters", None)
    annotations = getattr(tool, "annotations", None)
    if hasattr(tool, "model_dump"):
        dumped = tool.model_dump()
        if isinstance(dumped, dict):
            name = str(dumped.get("name", name))
            description = str(dumped.get("description", description) or "")
            parameters = dumped.get("parameters", parameters)
            annotations = dumped.get("annotations", annotations)
    normalized_annotations = dict(annotations) if isinstance(annotations, Mapping) else {}
    callable_tool = getattr(tool, "run", getattr(tool, "fn", tool))
    if callable(callable_tool) and _has_typed_return_annotation(callable_tool):
        normalized_annotations.setdefault("returns_typed_records", True)
    if annotation_overrides:
        normalized_annotations.update(annotation_overrides)
    return ToolSecuritySpec(
        name=name,
        description=description,
        parameters=parameters if isinstance(parameters, Mapping) else {},
        annotations=normalized_annotations,
    )


def _classification(
    name: str,
    effect: EffectClass,
    *,
    source: str,
    annotations: Mapping[str, Any] | None = None,
) -> ToolClassification:
    annotations = annotations or {}
    raw_neutral_args = annotations.get("neutral_args", ())
    if isinstance(raw_neutral_args, str):
        raw_neutral_args = (raw_neutral_args,)
    neutral_args = tuple(sorted(str(value) for value in raw_neutral_args))
    broadcast_sink = bool(annotations.get("broadcast_sink") or annotations.get("public_sink"))
    allow_content_after_untrusted = bool(annotations.get("allow_content_after_untrusted"))
    raw_lookup_args = annotations.get("authoritative_lookup_args")
    if isinstance(raw_lookup_args, str):
        raw_lookup_args = (raw_lookup_args,)
    authoritative_lookup_args = (
        tuple(sorted(str(value) for value in raw_lookup_args))
        if raw_lookup_args is not None
        else None
    )
    if effect is EffectClass.READ_AUTHORITATIVE:
        return ToolClassification(
            name=name,
            effect_class=effect,
            action="read",
            resource_id=f"tool:{name}",
            resource_label="effect.read_authoritative",
            requires_capability=False,
            classification_source=source,
            neutral_args=neutral_args,
            broadcast_sink=broadcast_sink,
            allow_content_after_untrusted=allow_content_after_untrusted,
            authoritative_lookup_args=authoritative_lookup_args,
        )
    if effect is EffectClass.READ_CONTENT:
        return ToolClassification(
            name=name,
            effect_class=effect,
            action="read",
            resource_id=f"tool:{name}",
            resource_label="effect.read_content",
            requires_capability=False,
            classification_source=source,
            neutral_args=neutral_args,
            broadcast_sink=broadcast_sink,
            allow_content_after_untrusted=allow_content_after_untrusted,
            authoritative_lookup_args=authoritative_lookup_args,
        )
    return ToolClassification(
        name=name,
        effect_class=effect,
        action="effect",
        resource_id=f"tool:{name}",
        resource_label="effect.effect",
        requires_capability=True,
        sink="external_or_mutating_effect",
        classification_source=source,
        neutral_args=neutral_args,
        broadcast_sink=broadcast_sink,
        allow_content_after_untrusted=allow_content_after_untrusted,
        authoritative_lookup_args=authoritative_lookup_args,
    )


def _explicit_effect(annotations: Mapping[str, Any]) -> EffectClass | None:
    value = annotations.get("effect_class") or annotations.get("x-vukzero-effect-class")
    if isinstance(value, EffectClass):
        return value
    if isinstance(value, str):
        try:
            return EffectClass(value.lower())
        except ValueError:
            return None
    if annotations.get("readOnlyHint") is True or annotations.get("read_only") is True:
        return EffectClass.READ_CONTENT
    return None


def _has_typed_return_annotation(fn: Any) -> bool:
    try:
        annotation = inspect.signature(fn).return_annotation
    except (TypeError, ValueError):
        return False
    return annotation not in {inspect.Signature.empty, None, Any, str, bytes}


def _tokens(value: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1 \2", value).lower())
