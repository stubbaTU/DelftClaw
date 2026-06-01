from __future__ import annotations

from security.preventative_layer.permissions import Capability, CapabilityStore


def test_capability_lifecycle_and_scope() -> None:
    store = CapabilityStore()
    cap = Capability(
        capability_id="cap_task_042_report",
        subject_id="agent_A0",
        allowed_action="write",
        resource_id="seedbox_report",
        resource_label="external.report_sink",
        task_id="task_042",
        expires_at_round=12,
    )
    store.issue(cap)

    assert store.has_valid_capability("agent_A0", "write", "seedbox_report", "external.report_sink", "task_042", 12)
    assert not store.has_valid_capability("agent_A1", "write", "seedbox_report", "external.report_sink", "task_042", 12)
    assert not store.has_valid_capability("agent_A0", "send", "seedbox_report", "external.report_sink", "task_042", 12)
    assert not store.has_valid_capability("agent_A0", "write", "seedbox_report", "external.report_sink", "task_043", 12)
    assert not store.has_valid_capability("agent_A0", "write", "seedbox_report", "external.report_sink", "task_042", 13)

    store.revoke("cap_task_042_report")
    assert not store.has_valid_capability("agent_A0", "write", "seedbox_report", "external.report_sink", "task_042", 12)
