"""VukZero permission system.

This package implements the Layer-1 Brain-vs-Hands reference monitor used by
VukZero. The LLM-facing brain may propose tool calls, but privileged hands
actions must pass through the permission engine and broker before execution.
"""

from security.preventative_layer.permissions.capability_store import CapabilityStore
from security.preventative_layer.permissions.decision_log import DecisionLog
from security.preventative_layer.permissions.egress_guard import EgressGuard
from security.preventative_layer.permissions.effects import (
    EffectClass,
    ToolClassification,
    ToolSecuritySpec,
    classify_tool,
    tool_security_spec,
)
from security.preventative_layer.permissions.models import (
    Capability,
    PermissionDecision,
    PermissionRequest,
    Resource,
    Subject,
    ValidationResult,
)
from security.preventative_layer.permissions.permission_engine import PermissionEngine
from security.preventative_layer.permissions.policy_loader import load_default_policy, load_policy
from security.preventative_layer.permissions.resource_registry import ResourceRegistry
from security.preventative_layer.permissions.provenance import Origin, ProvenanceStore, validate_effect_provenance
from security.preventative_layer.permissions.tool_broker import ToolBroker
from security.preventative_layer.permissions.validators import default_validator_registry

__all__ = [
    "Capability",
    "CapabilityStore",
    "DecisionLog",
    "EgressGuard",
    "EffectClass",
    "PermissionDecision",
    "PermissionEngine",
    "PermissionRequest",
    "Resource",
    "ResourceRegistry",
    "Subject",
    "ToolClassification",
    "ToolBroker",
    "ToolSecuritySpec",
    "ValidationResult",
    "ProvenanceStore",
    "Origin",
    "classify_tool",
    "default_validator_registry",
    "load_default_policy",
    "load_policy",
    "tool_security_spec",
    "validate_effect_provenance",
]
