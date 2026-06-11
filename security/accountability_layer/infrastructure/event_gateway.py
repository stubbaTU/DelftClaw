from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from security.accountability_layer.infrastructure.live_scenario_schema import (
    SQ2LiveEvent,
    SQ2LiveScenario,
    sanitized_event_for_agent,
)


EVENT_TYPE_TO_TOOL = {
    "microtask_assigned": "record_microtask_assigned",
    "microtask_reported": "claim_microtask_completed",
    "microtask_verified": "verify_microtask",
    "donation_broadcast": "broadcast_donation",
    "peer_endorsement": "endorse_peer",
    "security_report": "submit_security_report",
    "seedbox_benefit_request": "request_seedbox_benefit",
    "reward_redirect_attempt": "attempt_reward_redirect",
    "misleading_donation_claim": "submit_misleading_donation_claim",
}


@dataclass(frozen=True)
class GatewayResult:
    ok: bool
    reason: str
    canonical_event: dict[str, Any]


def normalize_reputation_tool_call(
    *,
    scenario: SQ2LiveScenario,
    condition: str,
    event: SQ2LiveEvent,
    tool_name: str,
    tool_args: dict[str, Any],
    source: str = "live_openclaw_tool_call",
) -> GatewayResult:
    """Convert a live SQ2 tool call into the canonical evaluator event.

    The frozen scenario remains the source of truth for event identity and
    payload. Live tool arguments are preserved as metadata and checked for
    obvious actor/tool mismatches, but hidden fields such as ground truth are
    never copied into the canonical event.
    """
    expected_tool = EVENT_TYPE_TO_TOOL.get(event.event_type)
    reasons: list[str] = []
    if expected_tool and tool_name != expected_tool:
        reasons.append(f"tool mismatch: expected {expected_tool}, got {tool_name}")

    actor_candidates = {
        value for value in [
            tool_args.get("actor_id"),
            tool_args.get("agent_id"),
            tool_args.get("from_agent"),
            tool_args.get("from"),
        ]
        if isinstance(value, str) and value
    }
    if actor_candidates and event.actor_id not in actor_candidates and event.event_type != "donation_broadcast":
        reasons.append(f"actor mismatch: expected {event.actor_id}, got {sorted(actor_candidates)}")

    visible_event = sanitized_event_for_agent(event)
    canonical = {
        "scenario_id": scenario.scenario_id,
        "condition": condition,
        "event_index": event.index,
        "round": event.round,
        "timestamp": event.timestamp,
        "actor_id": event.actor_id,
        "event_type": event.event_type,
        "payload": visible_event["payload"],
        "instruction": visible_event["instruction"],
        "source": source,
        "tool_name": tool_name,
        "tool_args": dict(tool_args),
        "expected_tool_name": expected_tool or "",
    }
    return GatewayResult(ok=not reasons, reason="; ".join(reasons) if reasons else "normalized", canonical_event=canonical)

