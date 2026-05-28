"""VukZero permission system.

This package implements the Layer-1 Brain-vs-Hands reference monitor used by
VukZero. The LLM-facing brain may propose tool calls, but privileged hands
actions must pass through the permission engine and broker before execution.
"""

from security.permissions.capability_store import CapabilityStore
from security.permissions.decision_log import DecisionLog
from security.permissions.egress_guard import EgressGuard
from security.permissions.models import (
    Capability,
    PermissionDecision,
    PermissionRequest,
    Resource,
    Subject,
    ValidationResult,
)
from security.permissions.permission_engine import PermissionEngine
from security.permissions.policy_loader import load_default_policy, load_policy
from security.permissions.resource_registry import ResourceRegistry
from security.permissions.tool_broker import ToolBroker
from security.permissions.validators import default_validator_registry

__all__ = [
    "Capability",
    "CapabilityStore",
    "DecisionLog",
    "EgressGuard",
    "PermissionDecision",
    "PermissionEngine",
    "PermissionRequest",
    "Resource",
    "ResourceRegistry",
    "Subject",
    "ToolBroker",
    "ValidationResult",
    "default_validator_registry",
    "load_default_policy",
    "load_policy",
]
