"""Integration helpers for connecting real OpenClaw agents to DelftClaw."""

from typing import Any

_OPENCLAW_TOOL_EXPORTS = {
    "EXPERIMENT_ONLY_TOOL_REGISTRY",
    "TOOL_REGISTRY",
    "delftclaw_audit_seedboxes",
    "delftclaw_broadcast_seedbox_donation",
    "delftclaw_get_metrics",
    "delftclaw_get_openclaw_status",
    "delftclaw_get_reputation",
    "delftclaw_register_seedbox",
    "delftclaw_report_security_event",
    "delftclaw_run_blocking_probe",
    "delftclaw_send_message",
    "delftclaw_submit_seedbox_proof",
    "tool_manifest",
}


def __getattr__(name: str) -> Any:
    if name == "DelftClawClient":
        from security.integration.client import DelftClawClient

        return DelftClawClient

    if name in _OPENCLAW_TOOL_EXPORTS:
        from security.integration import openclaw_tools

        return getattr(openclaw_tools, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    *_OPENCLAW_TOOL_EXPORTS,
]
