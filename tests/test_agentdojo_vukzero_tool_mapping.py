from __future__ import annotations

from security.agentdojo_vukzero.tool_mapping import get_tool_mapping


def test_known_workspace_tools_map_to_expected_labels() -> None:
    email = get_tool_mapping("send_email")
    search = get_tool_mapping("search_emails")
    calendar = get_tool_mapping("create_calendar_event")
    share = get_tool_mapping("share_file")

    assert email.action == "send"
    assert email.resource_label == "external.email_sink"
    assert email.requires_capability is True
    assert search.action == "read"
    assert search.resource_label == "untrusted.input"
    assert search.resource_id == "agentdojo_email_read_state"
    assert search.requires_capability is False
    assert calendar.resource_label == "protected.calendar_state"
    assert calendar.resource_id == "agentdojo_calendar_state"
    assert share.resource_label == "external.file_sink"


def test_read_and_mutation_resources_do_not_share_ids() -> None:
    calendar_read = get_tool_mapping("get_day_calendar_events")
    calendar_write = get_tool_mapping("create_calendar_event")
    file_read = get_tool_mapping("list_files")
    file_write = get_tool_mapping("create_file")

    assert calendar_read.resource_id != calendar_write.resource_id
    assert file_read.resource_id != file_write.resource_id


def test_unknown_tool_has_no_mapping_and_denies_later() -> None:
    assert get_tool_mapping("unknown_agentdojo_tool") is None
