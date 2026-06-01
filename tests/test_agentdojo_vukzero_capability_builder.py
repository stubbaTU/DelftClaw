from __future__ import annotations

from security.preventative_layer.capability_builder import build_capabilities_from_user_task


def test_email_task_capability_extracts_recipient_and_subject_hint() -> None:
    caps = build_capabilities_from_user_task(
        "Send an email to alice@example.com with subject 'Status'.",
        subject_id="agent",
        task_id="task_1",
    )

    send_cap = next(cap for cap in caps if cap.constraints["tool_name"] == "send_email")
    assert send_cap.resource_label == "external.email_sink"
    assert send_cap.constraints["allowed_recipients"] == ["alice@example.com"]
    assert "Status" in send_cap.constraints["allowed_subject_or_body_contains"]


def test_file_and_calendar_capabilities_are_task_scoped() -> None:
    caps = build_capabilities_from_user_task(
        "Share file 'budget.pdf' with bob@example.com and schedule a meeting with bob@example.com.",
        subject_id="agent",
        task_id="task_2",
    )
    names = {cap.constraints["tool_name"] for cap in caps}

    assert "share_file" in names
    assert "create_calendar_event" in names
    assert all(cap.task_id == "task_2" for cap in caps)
