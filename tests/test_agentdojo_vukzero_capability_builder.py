from __future__ import annotations

from security.preventative_layer.capability_builder import build_capabilities_from_user_task
from security.preventative_layer.permissions import ToolSecuritySpec


TOOLS = [
    ToolSecuritySpec(name="send_email"),
    ToolSecuritySpec(name="send_money"),
    ToolSecuritySpec(name="share_file"),
    ToolSecuritySpec(name="create_calendar_event"),
]


def test_email_task_capability_is_bound_to_effect_tool_and_task_literals() -> None:
    caps = build_capabilities_from_user_task(
        "Send an email to alice@example.com with subject 'Status'.",
        subject_id="agent",
        task_id="task_1",
        tool_specs=TOOLS,
    )

    send_cap = next(cap for cap in caps if cap.constraints["tool_name"] == "send_email")
    assert send_cap.resource_label == "effect.effect"
    assert send_cap.resource_id == "tool:send_email"
    assert send_cap.allowed_action == "effect"
    assert "alice@example.com" in send_cap.constraints["authorized_literals"]
    assert "status" in send_cap.constraints["authorized_literals"]


def test_file_and_calendar_capabilities_are_task_scoped() -> None:
    caps = build_capabilities_from_user_task(
        "Share file 'budget.pdf' with bob@example.com and schedule a meeting with bob@example.com.",
        subject_id="agent",
        task_id="task_2",
        tool_specs=TOOLS,
    )
    names = {cap.constraints["tool_name"] for cap in caps}

    assert "share_file" in names
    assert "create_calendar_event" in names
    assert all(cap.task_id == "task_2" for cap in caps)


def test_same_action_different_object_does_not_gain_capability() -> None:
    caps = build_capabilities_from_user_task(
        "Send money to account 'acct-7'.",
        subject_id="agent",
        task_id="task_money",
        tool_specs=TOOLS,
    )
    names = {cap.constraints["tool_name"] for cap in caps}

    assert "send_money" in names
    assert "send_email" not in names


def test_numeric_literal_can_be_bound_to_specific_capability_argument() -> None:
    tools = [
        ToolSecuritySpec(
            name="send_money",
            annotations={"bind_task_literals": {"amount": "amount"}},
        ),
    ]
    caps = build_capabilities_from_user_task(
        "Send $100 in money to account 'acct-7'.",
        subject_id="agent",
        task_id="task_bound_amount",
        tool_specs=tools,
    )

    assert caps[0].constraints["argument_literals"]["amount"] == ("number:100",)
