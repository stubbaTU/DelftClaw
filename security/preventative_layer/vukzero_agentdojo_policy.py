from __future__ import annotations

from security.preventative_layer.permissions.models import Policy, PolicyRule


PROVENANCE_RESOURCE_LABELS = {
    "effect.read_authoritative": {
        "description": "Read-only structured source whose identifier fields may establish trusted provenance",
    },
    "effect.read_content": {
        "description": "Read-only source whose returned values remain untrusted",
    },
    "effect.effect": {
        "description": "Any external or state-mutating effect requiring task authorization and trusted provenance",
    },
}


def build_provenance_policy() -> Policy:
    """Build the generic SQ1 provenance policy."""

    labels = dict(PROVENANCE_RESOURCE_LABELS)
    rules = [
        PolicyRule(
            "allow_authoritative_read",
            "normal_agent",
            "read",
            "allow",
            resource_label="effect.read_authoritative",
        ),
        PolicyRule(
            "allow_content_read",
            "normal_agent",
            "read",
            "allow",
            resource_label="effect.read_content",
        ),
        PolicyRule(
            "allow_task_scoped_effect",
            "normal_agent",
            "effect",
            "allow",
            resource_label="effect.effect",
            requires_capability=True,
            validators=("effect_argument_provenance", "egress_no_secret_canary"),
        ),
    ]
    return Policy(
        version=1,
        default_effect="deny",
        roles={"normal_agent": {"description": "Agent under VukZero provenance enforcement"}},
        resource_labels=labels,
        rules=tuple(rules),
    )


def build_agentdojo_policy() -> Policy:
    """Backward-compatible name for the generic provenance policy."""

    return build_provenance_policy()
