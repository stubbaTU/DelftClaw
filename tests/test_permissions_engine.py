from __future__ import annotations

from security.preventative_layer.infrastructure.permissions import (
    CapabilityStore,
    DecisionLog,
    PermissionEngine,
    PermissionRequest,
    Resource,
    ResourceRegistry,
    Subject,
    default_validator_registry,
    load_default_policy,
)


def _engine() -> tuple[PermissionEngine, ResourceRegistry, DecisionLog]:
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
    registry = ResourceRegistry()
    for resource in [
        Resource("task_input_001", "public.task"),
        Resource("identity_key", "secret.identity"),
        Resource("behavioral_log", "protected.log"),
        Resource("reputation_state", "protected.reputation"),
    ]:
        registry.register(resource)
    log = DecisionLog()
    return (
        PermissionEngine(policy, registry, CapabilityStore(), validators, log),
        registry,
        log,
    )


def _request(*, tool_name: str, action: str, resource_id: str) -> PermissionRequest:
    return PermissionRequest(
        request_id=f"req-{tool_name}",
        subject=Subject("agent_A0", "normal_agent"),
        tool_name=tool_name,
        action=action,
        resource_id=resource_id,
        resource_label=None,
        args={},
    )


def test_permission_engine_core_allow_and_deny_cases() -> None:
    engine, _registry, _log = _engine()

    assert engine.decide(_request(tool_name="load", action="read", resource_id="task_input_001")).decision == "allow"
    assert engine.decide(_request(tool_name="read_identity_key", action="read", resource_id="identity_key")).decision == "deny"
    assert engine.decide(_request(tool_name="rewrite_log", action="rewrite", resource_id="behavioral_log")).decision == "deny"
    assert engine.decide(_request(tool_name="mutate_reputation", action="mutate", resource_id="reputation_state")).decision == "deny"
    assert engine.decide(_request(tool_name="unknown", action="read", resource_id="missing")).decision == "deny"
