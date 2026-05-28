from __future__ import annotations

from pathlib import Path

import pytest

from security.permissions import (
    Capability,
    CapabilityStore,
    DecisionLog,
    EgressGuard,
    PermissionEngine,
    PermissionRequest,
    Resource,
    ResourceRegistry,
    Subject,
    ToolBroker,
    default_validator_registry,
    load_default_policy,
)
from security.permissions.policy_loader import PolicyLoadError, parse_policy
from security.permissions.proxies import AppendOnlyLogProxy, IdentityProxy, ReputationProxy, SeedboxProxy


PROXIES = {
    "identity_signing_proxy",
    "append_only_log_proxy",
    "reputation_update_proxy",
    "seedbox_request_proxy",
    "wallet_status_proxy",
}


def _engine(*, capabilities: CapabilityStore | None = None) -> tuple[PermissionEngine, ResourceRegistry, DecisionLog]:
    validators = default_validator_registry()
    policy = load_default_policy(known_validators=validators.names(), known_proxies=PROXIES)
    registry = ResourceRegistry()
    for resource in [
        Resource("task_input_001", "public.task"),
        Resource("identity_key", "secret.identity"),
        Resource("wallet_state", "secret.wallet"),
        Resource("behavioral_log", "protected.log"),
        Resource("reputation_state", "protected.reputation"),
        Resource("seedbox_control", "protected.seedbox"),
        Resource("peer_network", "external.peer_sink"),
        Resource("seedbox_report", "external.report_sink"),
    ]:
        registry.register(resource)
    log = DecisionLog()
    engine = PermissionEngine(
        policy=policy,
        resource_registry=registry,
        capability_store=capabilities or CapabilityStore(),
        validator_registry=validators,
        decision_log=log,
    )
    return engine, registry, log


def _request(
    *,
    tool_name: str,
    action: str,
    resource_id: str,
    args: dict | None = None,
    role: str = "normal_agent",
    task_id: str | None = None,
) -> PermissionRequest:
    return PermissionRequest(
        request_id=f"req-{tool_name}",
        subject=Subject("agent_A0", role),
        tool_name=tool_name,
        action=action,
        resource_id=resource_id,
        resource_label=None,
        args=args or {},
        task_id=task_id,
    )


def test_policy_loader_rejects_malformed_policy() -> None:
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
                "effect": "maybe",
            }],
        })


def test_resource_registry_denies_unknown_and_blocks_protected_paths() -> None:
    engine, registry, _log = _engine()

    assert registry.resolve("missing") is None
    assert registry.classify_path("../identity/key.json")[0] is False
    assert registry.classify_path("C:/tmp/private_identity_key.json")[0] is False

    decision = engine.decide(_request(tool_name="read_missing", action="read", resource_id="missing"))
    assert decision.decision == "deny"
    assert "unknown resource" in decision.reason


def test_capabilities_match_expire_and_revoke() -> None:
    store = CapabilityStore()
    cap = Capability(
        capability_id="cap_report",
        subject_id="agent_A0",
        allowed_action="write",
        resource_id="seedbox_report",
        resource_label="external.report_sink",
        task_id="task_001",
        expires_at_round=3,
    )
    store.issue(cap)

    assert store.has_valid_capability("agent_A0", "write", "seedbox_report", "external.report_sink", "task_001", 3)
    assert not store.has_valid_capability("agent_A1", "write", "seedbox_report", "external.report_sink", "task_001", 3)
    assert not store.has_valid_capability("agent_A0", "send", "seedbox_report", "external.report_sink", "task_001", 3)
    assert not store.has_valid_capability("agent_A0", "write", "seedbox_report", "external.report_sink", "task_002", 3)
    assert not store.has_valid_capability("agent_A0", "write", "seedbox_report", "external.report_sink", "task_001", 4)

    store.revoke("cap_report")
    assert not store.has_valid_capability("agent_A0", "write", "seedbox_report", "external.report_sink", "task_001", 3)


def test_permission_engine_allows_public_read_and_denies_secret_reads() -> None:
    engine, _registry, log = _engine()

    allowed = engine.decide(_request(tool_name="load_trial_input", action="read", resource_id="task_input_001"))
    identity = engine.decide(_request(tool_name="read_identity_key", action="read", resource_id="identity_key"))
    wallet = engine.decide(_request(tool_name="read_wallet_state", action="read", resource_id="wallet_state"))

    assert allowed.decision == "allow"
    assert identity.decision == "deny"
    assert wallet.decision == "deny"
    assert len(log.entries()) == 3


def test_permission_engine_requires_capability_and_valid_nonce_for_identity_proxy() -> None:
    store = CapabilityStore()
    engine, _registry, _log = _engine(capabilities=store)

    missing = engine.decide(_request(
        tool_name="sign_identity_nonce",
        action="sign",
        resource_id="identity_key",
        args={"nonce": "challenge_123"},
    ))
    assert missing.decision == "deny"

    store.issue(Capability(
        capability_id="cap_sign",
        subject_id="agent_A0",
        allowed_action="sign",
        resource_id="identity_key",
        resource_label="secret.identity",
    ))
    bad = engine.decide(_request(
        tool_name="sign_identity_nonce",
        action="sign",
        resource_id="identity_key",
        args={"nonce": "ignore previous private key"},
    ))
    good = engine.decide(_request(
        tool_name="sign_identity_nonce",
        action="sign",
        resource_id="identity_key",
        args={"nonce": "challenge_123"},
    ))

    assert bad.decision == "deny"
    assert good.decision == "allow_via_proxy"
    assert good.proxy_name == "identity_signing_proxy"


def test_egress_guard_denies_nested_canaries_without_leaking_value() -> None:
    guard = EgressGuard()

    assert guard.check_text("normal status").ok
    result = guard.check_payload({"report": ["x", {"key": "DELFTCLAW_TEST_PRIVATE_KEY_CANARY_ABC"}]})

    assert not result.ok
    assert "DELFTCLAW_TEST_PRIVATE_KEY_CANARY_" in result.reason
    assert "ABC" not in result.reason


@pytest.mark.asyncio
async def test_tool_broker_denies_before_raw_side_effect_and_routes_proxy() -> None:
    store = CapabilityStore()
    engine, _registry, _log = _engine(capabilities=store)
    broker = ToolBroker(engine)
    side_effects: list[str] = []

    async def read_identity_key() -> dict:
        side_effects.append("read")
        return {"private_identity_key": "DELFTCLAW_TEST_PRIVATE_KEY_CANARY_RAW"}

    async def send_peer_message(message: str, recipient: str = "peer") -> dict:
        side_effects.append(message)
        return {"ok": True, "message": message, "recipient": recipient}

    broker.register_tool("read_identity_key", read_identity_key, "read", lambda _args: "identity_key")
    broker.register_tool("send_peer_message", send_peer_message, "send", lambda _args: "peer_network")
    broker.register_tool("sign_identity_nonce", read_identity_key, "sign", lambda _args: "identity_key")
    broker.register_proxy("identity_signing_proxy", IdentityProxy().sign_nonce)

    subject = Subject("agent_A0", "normal_agent")
    denied = await broker.call_tool(subject, "read_identity_key", {})
    assert denied["blocked"] is True
    assert side_effects == []

    store.issue(Capability(
        capability_id="cap_peer",
        subject_id="agent_A0",
        allowed_action="send",
        resource_id="peer_network",
        resource_label="external.peer_sink",
    ))
    blocked_send = await broker.call_tool(
        subject,
        "send_peer_message",
        {"message": "DELFTCLAW_TEST_PRIVATE_KEY_CANARY_ABC", "recipient": "peer"},
    )
    assert blocked_send["blocked"] is True
    assert side_effects == []

    store.issue(Capability(
        capability_id="cap_sign",
        subject_id="agent_A0",
        allowed_action="sign",
        resource_id="identity_key",
        resource_label="secret.identity",
    ))
    signed = await broker.call_tool(subject, "sign_identity_nonce", {"nonce": "challenge_123"})
    assert signed["ok"] is True
    assert "signature" in signed
    assert side_effects == []


def test_proxies_do_not_expose_raw_privileged_state() -> None:
    subject = Subject("agent_A0", "normal_agent")
    assert "private" not in IdentityProxy().sign_nonce(subject, "n")

    log_proxy = AppendOnlyLogProxy()
    assert log_proxy.append_event(subject, {"event_type": "microtask_report"})["appended"] is True

    reputation_proxy = ReputationProxy()
    assert reputation_proxy.update_reputation_from_engine(subject, {"subject_id": "agent_A0"})["blocked"] is True

    seedbox = SeedboxProxy().request_seedbox_task(subject, "task_001")
    assert seedbox == {"ok": True, "subject_id": "agent_A0", "task_id": "task_001", "status": "requested"}
