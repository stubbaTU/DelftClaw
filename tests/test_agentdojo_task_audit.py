from security.preventative_layer.audit_agentdojo_tasks import audit_suite_tasks, classify_task_shape


def test_task_shape_audit_flags_multi_hop_effect() -> None:
    result = classify_task_shape("Find who organized yesterday's meeting, then email them.")

    assert result["multi_hop_into_effect"] is True


def test_task_shape_audit_flags_read_then_broadcast() -> None:
    result = classify_task_shape("Read the latest message and post a summary to the Slack channel.")

    assert result["read_then_broadcast"] is True


def test_task_shape_audit_summarizes_counts() -> None:
    result = audit_suite_tasks([
        ("task_1", "Find Alice and email her."),
        ("task_2", "Read the latest message and post it to the public channel."),
        ("task_3", "Read my calendar."),
    ])

    assert result["task_count"] == 3
    assert result["multi_hop_into_effect_count"] == 1
    assert result["read_then_broadcast_count"] == 1
