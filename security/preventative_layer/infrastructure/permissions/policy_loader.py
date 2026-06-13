from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from security.preventative_layer.infrastructure.permissions.models import DecisionEffect, Policy, PolicyRule


VALID_EFFECTS = {"allow", "deny", "allow_via_proxy"}
DEFAULT_POLICY_PATH = Path(__file__).with_name("default_policy.yaml")


class PolicyLoadError(ValueError):
    """Raised when a permission policy is malformed."""


def load_default_policy(
    *,
    known_validators: set[str] | None = None,
    known_proxies: set[str] | None = None,
) -> Policy:
    return load_policy(
        DEFAULT_POLICY_PATH,
        known_validators=known_validators,
        known_proxies=known_proxies,
    )


def load_policy(
    path: str | Path,
    *,
    known_validators: set[str] | None = None,
    known_proxies: set[str] | None = None,
) -> Policy:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise PolicyLoadError("policy must be a mapping")
    return parse_policy(data, known_validators=known_validators, known_proxies=known_proxies)


def parse_policy(
    data: dict[str, Any],
    *,
    known_validators: set[str] | None = None,
    known_proxies: set[str] | None = None,
) -> Policy:
    """Validate an in-memory policy mapping and return a typed ``Policy``."""
    version = data.get("version")
    if not isinstance(version, int):
        raise PolicyLoadError("policy.version must be an integer")
    if data.get("default_effect") != "deny":
        raise PolicyLoadError("policy.default_effect must be deny")

    roles = _mapping(data, "roles")
    resource_labels = _mapping(data, "resource_labels")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise PolicyLoadError("policy.rules must be a list")

    rules: list[PolicyRule] = []
    seen_ids: set[str] = set()
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise PolicyLoadError(f"rules[{index}] must be a mapping")
        rule = _parse_rule(raw_rule, index)
        if rule.id in seen_ids:
            raise PolicyLoadError(f"duplicate rule id: {rule.id}")
        seen_ids.add(rule.id)
        if rule.role not in roles:
            raise PolicyLoadError(f"rule {rule.id} references unknown role {rule.role}")
        if rule.resource_label is not None and rule.resource_label not in resource_labels:
            raise PolicyLoadError(f"rule {rule.id} references unknown resource label {rule.resource_label}")
        if known_validators is not None:
            unknown = sorted(set(rule.validators) - known_validators)
            if unknown:
                raise PolicyLoadError(f"rule {rule.id} references unknown validators {unknown}")
        if rule.effect == "allow_via_proxy":
            if not rule.proxy:
                raise PolicyLoadError(f"rule {rule.id} allow_via_proxy requires proxy")
            if known_proxies is not None and rule.proxy not in known_proxies:
                raise PolicyLoadError(f"rule {rule.id} references unknown proxy {rule.proxy}")
        rules.append(rule)

    return Policy(
        version=version,
        default_effect="deny",
        roles=dict(roles),
        resource_labels=dict(resource_labels),
        rules=tuple(rules),
    )


def _mapping(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise PolicyLoadError(f"policy.{key} must be a mapping")
    return value


def _parse_rule(raw: dict[str, Any], index: int) -> PolicyRule:
    for field in ("id", "role", "action", "effect"):
        if not isinstance(raw.get(field), str) or not raw[field]:
            raise PolicyLoadError(f"rules[{index}].{field} must be a non-empty string")
    effect = raw["effect"]
    if effect not in VALID_EFFECTS:
        raise PolicyLoadError(f"rules[{index}] has unknown effect {effect!r}")
    validators = raw.get("validators", [])
    if validators is None:
        validators = []
    if not isinstance(validators, list) or not all(isinstance(item, str) for item in validators):
        raise PolicyLoadError(f"rules[{index}].validators must be a list of strings")
    requires_capability = raw.get("requires_capability", False)
    if not isinstance(requires_capability, bool):
        raise PolicyLoadError(f"rules[{index}].requires_capability must be boolean")
    resource_label = raw.get("resource_label")
    resource_id = raw.get("resource_id")
    proxy = raw.get("proxy")
    for name, value in (("resource_label", resource_label), ("resource_id", resource_id), ("proxy", proxy)):
        if value is not None and not isinstance(value, str):
            raise PolicyLoadError(f"rules[{index}].{name} must be a string when present")
    if resource_label is None and resource_id is None:
        raise PolicyLoadError(f"rules[{index}] must include resource_label or resource_id")
    return PolicyRule(
        id=raw["id"],
        role=raw["role"],
        action=raw["action"],
        resource_label=resource_label,
        resource_id=resource_id,
        effect=effect,  # type: ignore[arg-type]
        proxy=proxy,
        requires_capability=requires_capability,
        validators=tuple(validators),
    )
