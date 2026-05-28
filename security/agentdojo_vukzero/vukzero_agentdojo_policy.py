from __future__ import annotations

from security.agentdojo_vukzero.tool_mapping import all_resource_labels
from security.permissions.models import Policy, PolicyRule


AGENTDOJO_RESOURCE_LABELS = {
    "external.email_sink": {"description": "Outgoing AgentDojo email sink"},
    "external.file_sink": {"description": "Outgoing AgentDojo file-share sink"},
    "external.slack_sink": {"description": "Outgoing AgentDojo Slack sink"},
    "external.banking_sink": {"description": "Outgoing AgentDojo banking sink"},
    "external.travel_sink": {"description": "Outgoing AgentDojo travel booking sink"},
    "protected.email_state": {"description": "Mutable AgentDojo email state"},
    "protected.calendar_state": {"description": "Mutable AgentDojo calendar state"},
    "protected.file_state": {"description": "Mutable AgentDojo file state"},
    "protected.slack_state": {"description": "Mutable AgentDojo Slack state"},
    "protected.banking_state": {"description": "Mutable AgentDojo banking state"},
    "protected.travel_state": {"description": "Mutable AgentDojo travel state"},
    "public.task": {"description": "Public task context"},
    "untrusted.input": {"description": "Untrusted environment/tool data"},
}


def build_agentdojo_policy() -> Policy:
    labels = dict(AGENTDOJO_RESOURCE_LABELS)
    for label in all_resource_labels():
        labels.setdefault(label, {"description": f"AgentDojo label {label}"})
    rules = [
        PolicyRule("agentdojo_allow_public_read", "normal_agent", "read", "allow", resource_label="public.task"),
        PolicyRule("agentdojo_allow_untrusted_read", "normal_agent", "read", "allow", resource_label="untrusted.input"),
    ]
    external_labels = sorted(label for label in labels if label.startswith("external."))
    protected_labels = sorted(label for label in labels if label.startswith("protected."))
    for label in external_labels:
        for action in ("send", "write", "request"):
            rules.append(PolicyRule(
                id=f"agentdojo_allow_{action}_{_safe(label)}",
                role="normal_agent",
                action=action,
                resource_label=label,
                effect="allow",
                requires_capability=True,
                validators=("agentdojo_capability_constraints", "agentdojo_external_sink_egress"),
            ))
    for label in protected_labels:
        for action in ("write", "append", "delete", "mutate", "send", "request"):
            rules.append(PolicyRule(
                id=f"agentdojo_allow_{action}_{_safe(label)}",
                role="normal_agent",
                action=action,
                resource_label=label,
                effect="allow",
                requires_capability=True,
                validators=("agentdojo_capability_constraints",),
            ))
    return Policy(
        version=1,
        default_effect="deny",
        roles={"normal_agent": {"description": "AgentDojo agent under VukZero"}},
        resource_labels=labels,
        rules=tuple(rules),
    )


def _safe(value: str) -> str:
    return value.replace(".", "_").replace("-", "_")
