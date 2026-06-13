from typing import Any

from security.preventative_layer.infrastructure.permissions.models import Policy, PolicyRule
from security.preventative_layer.infrastructure.permissions.policy_loader import PolicyLoadError, parse_policy


def validate_policy_schema(
    data: dict[str, Any],
    *,
    known_validators: set[str] | None = None,
    known_proxies: set[str] | None = None,
) -> Policy:
    """Validate an in-memory policy mapping and return a typed ``Policy``."""

    return parse_policy(data, known_validators=known_validators, known_proxies=known_proxies)


__all__ = ["Policy", "PolicyLoadError", "PolicyRule", "validate_policy_schema"]
