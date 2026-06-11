from __future__ import annotations

import pytest

from security.preventative_layer.infrastructure.permissions import default_validator_registry, load_default_policy
from security.preventative_layer.infrastructure.permissions.policy_loader import PolicyLoadError, parse_policy


def test_loads_valid_default_policy() -> None:
    validators = default_validator_registry()
    policy = load_default_policy(
        known_validators=validators.names(),
        known_proxies={
            "identity_signing_proxy",
            "wallet_status_proxy",
            "append_only_log_proxy",
            "reputation_update_proxy",
            "seedbox_request_proxy",
        },
    )

    assert policy.default_effect == "deny"
    assert any(rule.id == "deny_direct_identity_read" for rule in policy.rules)


def test_rejects_malformed_policy_and_unknown_effect() -> None:
    with pytest.raises(PolicyLoadError):
        parse_policy({"version": 1, "default_effect": "allow", "roles": {}, "resource_labels": {}, "rules": []})

    with pytest.raises(PolicyLoadError):
        parse_policy({
            "version": 1,
            "default_effect": "deny",
            "roles": {"normal_agent": {}},
            "resource_labels": {"public.task": {}},
            "rules": [{
                "id": "bad",
                "role": "normal_agent",
                "action": "read",
                "resource_label": "public.task",
                "effect": "unknown",
            }],
        })


def test_rejects_unknown_validators_and_proxies_in_strict_mode() -> None:
    with pytest.raises(PolicyLoadError):
        parse_policy({
            "version": 1,
            "default_effect": "deny",
            "roles": {"normal_agent": {}},
            "resource_labels": {"secret.identity": {}},
            "rules": [{
                "id": "bad_validator",
                "role": "normal_agent",
                "action": "sign",
                "resource_label": "secret.identity",
                "effect": "allow_via_proxy",
                "proxy": "identity_signing_proxy",
                "validators": ["missing_validator"],
            }],
        }, known_validators=set(), known_proxies={"identity_signing_proxy"})

    with pytest.raises(PolicyLoadError):
        parse_policy({
            "version": 1,
            "default_effect": "deny",
            "roles": {"normal_agent": {}},
            "resource_labels": {"secret.identity": {}},
            "rules": [{
                "id": "bad_proxy",
                "role": "normal_agent",
                "action": "sign",
                "resource_label": "secret.identity",
                "effect": "allow_via_proxy",
                "proxy": "missing_proxy",
            }],
        }, known_validators=set(), known_proxies=set())
