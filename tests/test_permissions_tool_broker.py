from __future__ import annotations

import pytest

from security.preventative_layer.permissions import (
    Capability,
    CapabilityStore,
    DecisionLog,
    PermissionEngine,
    Resource,
    ResourceRegistry,
    Subject,
    ToolBroker,
    default_validator_registry,
    load_default_policy,
)
from security.preventative_layer.permissions.proxies import IdentityProxy


def _engine(*, capabilities: CapabilityStore) -> tuple[PermissionEngine, ResourceRegistry, DecisionLog]:
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
    registry.register(Resource("identity_key", "secret.identity"))
    log = DecisionLog()
    return PermissionEngine(policy, registry, capabilities, validators, log), registry, log


@pytest.mark.asyncio
async def test_tool_broker_blocks_side_effects_and_routes_proxy() -> None:
    store = CapabilityStore()
    engine, _registry, _log = _engine(capabilities=store)
    broker = ToolBroker(engine)
    effects: list[str] = []

    async def raw_secret() -> dict:
        effects.append("raw")
        return {"private_identity_key": "secret"}

    broker.register_tool("read_identity_key", raw_secret, "read", lambda _args: "identity_key")
    broker.register_tool("sign_identity_nonce", raw_secret, "sign", lambda _args: "identity_key")
    broker.register_proxy("identity_signing_proxy", IdentityProxy().sign_nonce)

    subject = Subject("agent_A0", "normal_agent")
    denied = await broker.call_tool(subject, "read_identity_key", {})
    assert denied["blocked"] is True
    assert effects == []

    store.issue(Capability("cap_sign", "agent_A0", "sign", resource_id="identity_key", resource_label="secret.identity"))
    signed = await broker.call_tool(subject, "sign_identity_nonce", {"nonce": "challenge"})
    assert signed["ok"] is True
    assert effects == []
