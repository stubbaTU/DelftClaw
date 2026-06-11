from __future__ import annotations

import os
from typing import Any

from security.preventative_layer.infrastructure.permissions.capability_store import CapabilityStore
from security.preventative_layer.infrastructure.permissions.decision_log import DecisionLog
from security.preventative_layer.infrastructure.permissions.egress_guard import EgressGuard
from security.preventative_layer.infrastructure.permissions.models import Capability, Resource, Subject
from security.preventative_layer.infrastructure.permissions.models import PermissionDecision, PermissionRequest
from security.preventative_layer.infrastructure.permissions.permission_engine import PermissionEngine
from security.preventative_layer.infrastructure.permissions.policy_loader import load_default_policy
from security.preventative_layer.infrastructure.permissions.proxies import AppendOnlyLogProxy, IdentityProxy, ReputationProxy, SeedboxProxy, WalletProxy
from security.preventative_layer.infrastructure.permissions.resource_registry import ResourceRegistry
from security.preventative_layer.infrastructure.permissions.tool_broker import ToolBroker
from security.preventative_layer.infrastructure.permissions.validators import default_validator_registry


READ_PUBLIC_NETWORK = {
    "peers_list",
    "community_log_list_recent",
    "community_treasury_balance",
    "community_member_count",
    "overlays_list",
    "overlay_describe",
    "torrent_stats",
}
READ_PUBLIC_WALLET = {"wallet_address", "wallet_balance"}
WALLET_REQUEST = {"wallet_send"}
COMMUNITY_LOG_APPEND = {
    "community_donate_and_join",
    "seedbox_purchase_propose",
    "seedbox_provisioned",
    "community_join_via_peer",
}
SEEDBOX_COMMAND = {
    "peer_add",
    "overlay_fetch_and_load",
    "overlay_publish",
    "agent_inject_manifest",
    "overlay_invoke",
    "torrent_seed",
    "torrent_fetch",
    "content_search_and_fetch",
    "seedbox_donate_and_join",
    "network_join",
}


def permissions_enabled(config: Any) -> bool:
    env = os.getenv("VUKZERO_PERMISSION_SYSTEM")
    if env is not None and env.strip():
        return env.strip().lower() in {"1", "true", "yes", "enabled", "on"}
    configured = getattr(config, "permissions_enabled", None)
    if configured is not None:
        return bool(configured)
    return True


def build_permissioned_registry(agent: Any, tools: list[Any], tool_cls: Any, registry_cls: Any) -> Any:
    subject = Subject(subject_id=_agent_subject_id(agent), role="normal_agent")
    validators = default_validator_registry()
    proxies = _proxy_map()
    policy = load_default_policy(
        known_validators=validators.names(),
        known_proxies=set(proxies),
    )
    resources = ResourceRegistry()
    capabilities = CapabilityStore()
    for tool in tools:
        classification = classify_openclaw_tool(tool.name)
        resources.register(Resource(
            resource_id=classification["resource_id"],
            label=classification["resource_label"],
        ))
        if classification["requires_capability"]:
            capabilities.issue(Capability(
                capability_id=f"cap_{subject.subject_id}_{tool.name}",
                subject_id=subject.subject_id,
                allowed_action=classification["action"],
                resource_id=classification["resource_id"],
                resource_label=classification["resource_label"],
            ))

    decision_log = DecisionLog()
    engine = PermissionEngine(
        policy=policy,
        resource_registry=resources,
        capability_store=capabilities,
        validator_registry=validators,
        decision_log=decision_log,
    )
    broker = ToolBroker(engine)
    for proxy_name, proxy_fn in proxies.items():
        broker.register_proxy(proxy_name, proxy_fn)
    for tool in tools:
        classification = classify_openclaw_tool(tool.name)
        broker.register_tool(
            tool.name,
            tool.fn,
            classification["action"],
            lambda _args, resource_id=classification["resource_id"]: resource_id,
            sink=classification["sink"],
        )

    wrapped_tools = [
        tool_cls(
            tool.name,
            tool.description,
            tool.parameters,
            _wrap_tool(subject, broker, tool.name),
        )
        for tool in tools
    ]
    registry = registry_cls(wrapped_tools)
    registry.permission_engine = engine
    registry.permission_decision_log = decision_log
    registry.permission_broker = broker
    registry.check_final_output = _build_final_output_checker(EgressGuard())
    return registry


def classify_openclaw_tool(tool_name: str) -> dict[str, Any]:
    if tool_name in READ_PUBLIC_NETWORK:
        return _classification(tool_name, "read", "public.network", False)
    if tool_name in READ_PUBLIC_WALLET:
        return _classification(tool_name, "read", "public.wallet", False)
    if tool_name in WALLET_REQUEST:
        return _classification(tool_name, "request", "protected.wallet", True)
    if tool_name in COMMUNITY_LOG_APPEND:
        return _classification(tool_name, "append", "protected.community_log", True)
    if tool_name in SEEDBOX_COMMAND:
        return _classification(tool_name, "request", "protected.seedbox_command", True)
    # Unknown or newly added tools must never silently inherit a safe class.
    # Until trusted deployment metadata classifies them more precisely, treat
    # them as privileged effects requiring an explicit capability.
    return _classification(tool_name, "request", "protected.seedbox_command", True)


def authorize_openclaw_tool(agent: Any, tool_name: str, args: dict[str, Any]) -> PermissionDecision:
    """Authorize an OpenClaw/MCP tool call without executing it.

    This is used for MCP-only composite tools that are not part of
    ``agent.tools.build_tools`` but still need the same policy boundary before
    their raw implementation performs wallet, seedbox, or network actions.
    """

    subject = Subject(subject_id=_agent_subject_id(agent), role="normal_agent")
    classification = classify_openclaw_tool(tool_name)
    validators = default_validator_registry()
    proxies = _proxy_map()
    policy = load_default_policy(
        known_validators=validators.names(),
        known_proxies=set(proxies),
    )
    resources = ResourceRegistry()
    resources.register(Resource(
        resource_id=classification["resource_id"],
        label=classification["resource_label"],
    ))
    capabilities = CapabilityStore()
    if classification["requires_capability"]:
        capabilities.issue(Capability(
            capability_id=f"cap_{subject.subject_id}_{tool_name}",
            subject_id=subject.subject_id,
            allowed_action=classification["action"],
            resource_id=classification["resource_id"],
            resource_label=classification["resource_label"],
        ))
    engine = PermissionEngine(
        policy=policy,
        resource_registry=resources,
        capability_store=capabilities,
        validator_registry=validators,
        decision_log=DecisionLog(),
    )
    return engine.decide(PermissionRequest(
        request_id=f"mcp-{tool_name}",
        subject=subject,
        tool_name=tool_name,
        action=classification["action"],
        resource_id=classification["resource_id"],
        resource_label=None,
        args=args,
        sink=classification["sink"],
    ))


def _classification(tool_name: str, action: str, resource_label: str, requires_capability: bool) -> dict[str, Any]:
    return {
        "resource_id": f"openclaw_tool:{tool_name}",
        "resource_label": resource_label,
        "action": action,
        "requires_capability": requires_capability,
        "sink": _sink_for(tool_name),
    }


def _sink_for(tool_name: str) -> str | None:
    if tool_name in {"peer_add", "overlay_fetch_and_load", "overlay_invoke", "content_search_and_fetch"}:
        return "external.peer_sink"
    if tool_name in {"overlay_publish", "agent_inject_manifest", "torrent_seed", "torrent_fetch"}:
        return "external.report_sink"
    return None


def _wrap_tool(subject: Subject, broker: ToolBroker, tool_name: str):
    async def wrapper(**kwargs: Any) -> Any:
        return await broker.call_tool(subject=subject, tool_name=tool_name, args=kwargs)

    return wrapper


def _build_final_output_checker(guard: EgressGuard):
    def check_final_output(text: str) -> str:
        result = guard.check_text(text)
        if result.ok:
            return text
        return f"[permission_denied: final output blocked: {result.reason}]"

    return check_final_output


def _proxy_map() -> dict[str, Any]:
    return {
        "identity_signing_proxy": IdentityProxy().sign_nonce,
        "wallet_status_proxy": WalletProxy().get_public_wallet_status,
        "append_only_log_proxy": AppendOnlyLogProxy().append_event,
        "reputation_update_proxy": ReputationProxy().update_reputation_from_engine,
        "seedbox_request_proxy": SeedboxProxy().request_seedbox_task,
    }


def _agent_subject_id(agent: Any) -> str:
    identity = getattr(agent, "identity", None)
    identity_hash = getattr(identity, "identity_hash", None)
    if isinstance(identity_hash, str) and identity_hash:
        return identity_hash
    if callable(identity_hash):
        value = identity_hash()
        if isinstance(value, str) and value:
            return value
    return "openclaw_agent"
