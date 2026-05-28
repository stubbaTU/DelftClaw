from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AgentDojoToolMapping:
    tool_name: str
    action: str
    resource_id: str
    resource_label: str
    requires_capability: bool = False
    sink: str | None = None
    validator: str | None = None


AGENTDOJO_TOOL_MAP: dict[str, dict[str, Any]] = {
    "send_email": {
        "action": "send",
        "resource_id": "agentdojo_email_outbox",
        "resource_label": "external.email_sink",
        "sink": "email",
        "requires_capability": True,
        "validator": "agentdojo_send_email_capability",
    },
    "delete_email": {
        "action": "delete",
        "resource_id": "agentdojo_email_state",
        "resource_label": "protected.email_state",
        "requires_capability": True,
    },
    "search_emails": {"action": "read", "resource_id": "agentdojo_email_read_state", "resource_label": "untrusted.input"},
    "get_unread_emails": {"action": "read", "resource_id": "agentdojo_email_read_state", "resource_label": "untrusted.input"},
    "get_received_emails": {"action": "read", "resource_id": "agentdojo_email_read_state", "resource_label": "untrusted.input"},
    "get_sent_emails": {"action": "read", "resource_id": "agentdojo_email_read_state", "resource_label": "untrusted.input"},
    "get_draft_emails": {"action": "read", "resource_id": "agentdojo_email_read_state", "resource_label": "untrusted.input"},
    "search_contacts_by_name": {"action": "read", "resource_id": "agentdojo_contacts", "resource_label": "public.task"},
    "search_contacts_by_email": {"action": "read", "resource_id": "agentdojo_contacts", "resource_label": "public.task"},
    "create_calendar_event": {
        "action": "write",
        "resource_id": "agentdojo_calendar_state",
        "resource_label": "protected.calendar_state",
        "requires_capability": True,
        "validator": "agentdojo_calendar_capability",
    },
    "cancel_calendar_event": {
        "action": "delete",
        "resource_id": "agentdojo_calendar_state",
        "resource_label": "protected.calendar_state",
        "requires_capability": True,
        "validator": "agentdojo_calendar_capability",
    },
    "reschedule_calendar_event": {
        "action": "mutate",
        "resource_id": "agentdojo_calendar_state",
        "resource_label": "protected.calendar_state",
        "requires_capability": True,
        "validator": "agentdojo_calendar_capability",
    },
    "add_calendar_event_participants": {
        "action": "mutate",
        "resource_id": "agentdojo_calendar_state",
        "resource_label": "protected.calendar_state",
        "requires_capability": True,
        "validator": "agentdojo_calendar_capability",
    },
    "search_calendar_events": {"action": "read", "resource_id": "agentdojo_calendar_read_state", "resource_label": "untrusted.input"},
    "get_day_calendar_events": {"action": "read", "resource_id": "agentdojo_calendar_read_state", "resource_label": "untrusted.input"},
    "get_current_day": {"action": "read", "resource_id": "agentdojo_clock", "resource_label": "public.task"},
    "create_file": {
        "action": "write",
        "resource_id": "agentdojo_file_state",
        "resource_label": "protected.file_state",
        "requires_capability": True,
        "validator": "agentdojo_file_mutation_capability",
    },
    "append_to_file": {
        "action": "append",
        "resource_id": "agentdojo_file_state",
        "resource_label": "protected.file_state",
        "requires_capability": True,
        "validator": "agentdojo_file_mutation_capability",
    },
    "delete_file": {
        "action": "delete",
        "resource_id": "agentdojo_file_state",
        "resource_label": "protected.file_state",
        "requires_capability": True,
        "validator": "agentdojo_file_mutation_capability",
    },
    "share_file": {
        "action": "send",
        "resource_id": "agentdojo_file_share_sink",
        "resource_label": "external.file_sink",
        "sink": "file_share",
        "requires_capability": True,
        "validator": "agentdojo_file_share_capability",
    },
    "search_files": {"action": "read", "resource_id": "agentdojo_file_read_state", "resource_label": "untrusted.input"},
    "search_files_by_filename": {"action": "read", "resource_id": "agentdojo_file_read_state", "resource_label": "untrusted.input"},
    "get_file_by_id": {"action": "read", "resource_id": "agentdojo_file_read_state", "resource_label": "untrusted.input"},
    "list_files": {"action": "read", "resource_id": "agentdojo_file_read_state", "resource_label": "untrusted.input"},
}


SLACK_TOOL_MAP = {
    "send_slack_message": {
        "action": "send",
        "resource_id": "agentdojo_slack_sink",
        "resource_label": "external.slack_sink",
        "sink": "slack",
        "requires_capability": True,
    },
    "read_slack_messages": {"action": "read", "resource_id": "agentdojo_slack_state", "resource_label": "untrusted.input"},
    "get_slack_channels": {"action": "read", "resource_id": "agentdojo_slack_state", "resource_label": "public.task"},
}

BANKING_TOOL_MAP = {
    "send_money": {
        "action": "send",
        "resource_id": "agentdojo_banking_sink",
        "resource_label": "external.banking_sink",
        "sink": "banking",
        "requires_capability": True,
    },
    "transfer_money": {
        "action": "send",
        "resource_id": "agentdojo_banking_sink",
        "resource_label": "external.banking_sink",
        "sink": "banking",
        "requires_capability": True,
    },
    "get_balance": {"action": "read", "resource_id": "agentdojo_banking_state", "resource_label": "public.task"},
    "get_transactions": {"action": "read", "resource_id": "agentdojo_banking_state", "resource_label": "untrusted.input"},
}

TRAVEL_TOOL_MAP = {
    "book_flight": {
        "action": "request",
        "resource_id": "agentdojo_travel_sink",
        "resource_label": "external.travel_sink",
        "sink": "travel",
        "requires_capability": True,
    },
    "book_hotel": {
        "action": "request",
        "resource_id": "agentdojo_travel_sink",
        "resource_label": "external.travel_sink",
        "sink": "travel",
        "requires_capability": True,
    },
    "search_flights": {"action": "read", "resource_id": "agentdojo_travel_state", "resource_label": "untrusted.input"},
    "search_hotels": {"action": "read", "resource_id": "agentdojo_travel_state", "resource_label": "untrusted.input"},
}

AGENTDOJO_TOOL_MAP.update(SLACK_TOOL_MAP)
AGENTDOJO_TOOL_MAP.update(BANKING_TOOL_MAP)
AGENTDOJO_TOOL_MAP.update(TRAVEL_TOOL_MAP)


def get_tool_mapping(tool_name: str) -> AgentDojoToolMapping | None:
    raw = AGENTDOJO_TOOL_MAP.get(tool_name)
    if raw is None:
        return None
    return AgentDojoToolMapping(tool_name=tool_name, **raw)


def all_resource_ids() -> set[str]:
    return {mapping["resource_id"] for mapping in AGENTDOJO_TOOL_MAP.values()}


def all_resource_labels() -> set[str]:
    return {mapping["resource_label"] for mapping in AGENTDOJO_TOOL_MAP.values()}
