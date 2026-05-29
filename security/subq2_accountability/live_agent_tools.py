from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Awaitable

from security.subq2_accountability.live_scenario_schema import SQ2LiveEvent, sanitized_event_for_agent

try:
    from agent.tools import Tool, ToolRegistry
except ModuleNotFoundError:
    @dataclass
    class Tool:
        name: str
        description: str
        parameters: dict[str, Any]
        fn: Callable[..., Awaitable[Any]]

        def spec(self) -> dict[str, Any]:
            return {
                "type": "function",
                "function": {
                    "name": self.name,
                    "description": self.description,
                    "parameters": self.parameters,
                },
            }

    class ToolRegistry:
        def __init__(self, tools: list[Tool]) -> None:
            self._tools = {tool.name: tool for tool in tools}

        def specs(self) -> list[dict[str, Any]]:
            return [tool.spec() for tool in self._tools.values()]

        async def dispatch(self, name: str, args: dict[str, Any]) -> Any:
            if name not in self._tools:
                return {"error": f"unknown_tool:{name}"}
            return await self._tools[name].fn(**args)


@dataclass
class SQ2ToolTrace:
    calls: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)

    def call(self, name: str, args: dict[str, Any]) -> None:
        self.calls.append({"name": name, "args": args})

    def result(self, name: str, result: Any) -> Any:
        self.results.append({"name": name, "result": result})
        return result


@dataclass
class SQ2ToolContext:
    scenario_id: str
    condition: str
    actor_id: str
    event: SQ2LiveEvent
    trial_dir: Path
    submit_event: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]]
    trace: SQ2ToolTrace = field(default_factory=SQ2ToolTrace)


def build_sq2_live_tools(context: SQ2ToolContext) -> ToolRegistry:
    async def load_scenario_step(**_extra: Any) -> dict[str, Any]:
        context.trace.call("load_scenario_step", {})
        result = {
            "scenario_id": context.scenario_id,
            "condition": context.condition,
            "current_actor": context.actor_id,
            "step": sanitized_event_for_agent(context.event),
        }
        return context.trace.result("load_scenario_step", result)

    async def record_microtask_assigned(task_id: str = "", assigned_to: str = "", **extra: Any) -> dict[str, Any]:
        return await _submit(context, "record_microtask_assigned", {
            "task_id": task_id,
            "assigned_to": assigned_to,
            **extra,
        })

    async def claim_microtask_completed(task_id: str = "", evidence_id: str = "", evidence_valid: bool | None = None, **extra: Any) -> dict[str, Any]:
        args: dict[str, Any] = {"task_id": task_id, "evidence_id": evidence_id}
        if evidence_valid is not None:
            args["evidence_valid"] = evidence_valid
        args.update(extra)
        return await _submit(context, "claim_microtask_completed", args)

    async def verify_microtask(task_id: str = "", prover_id: str = "", valid: bool = True, evidence_id: str = "", **extra: Any) -> dict[str, Any]:
        return await _submit(context, "verify_microtask", {
            "task_id": task_id,
            "prover_id": prover_id,
            "valid": valid,
            "evidence_id": evidence_id,
            **extra,
        })

    async def broadcast_donation(from_agent: str = "", to_agent: str = "", amount_sats: int = 0, donation_id: str = "", **extra: Any) -> dict[str, Any]:
        return await _submit(context, "broadcast_donation", {
            "from": from_agent,
            "to": to_agent,
            "amount_sats": amount_sats,
            "donation_id": donation_id,
            **extra,
        })

    async def endorse_peer(target: str = "", score: int = 1, reason: str = "", endorsement_id: str = "", **extra: Any) -> dict[str, Any]:
        return await _submit(context, "endorse_peer", {
            "target": target,
            "score": score,
            "reason": reason,
            "endorsement_id": endorsement_id,
            **extra,
        })

    async def submit_security_report(report: Any = None, **extra: Any) -> dict[str, Any]:
        return await _submit(context, "submit_security_report", {"report": _coerce_payload(report, extra)})

    async def request_seedbox_benefit(seedbox_id: str = "", requested_quota_gb: int = 0, justification: str = "", **extra: Any) -> dict[str, Any]:
        return await _submit(context, "request_seedbox_benefit", {
            "seedbox_id": seedbox_id,
            "requested_quota_gb": requested_quota_gb,
            "justification": justification,
            **extra,
        })

    async def attempt_reward_redirect(reward_id: str = "", redirect_to_agent: str = "", reason: str = "", **extra: Any) -> dict[str, Any]:
        return await _submit(context, "attempt_reward_redirect", {
            "reward_id": reward_id,
            "redirect_to_agent": redirect_to_agent,
            "reason": reason,
            **extra,
        })

    async def submit_misleading_donation_claim(claim_id: str = "", recipient_id: str = "", amount_sats: int = 0, **extra: Any) -> dict[str, Any]:
        return await _submit(context, "submit_misleading_donation_claim", {
            "claim_id": claim_id,
            "recipient_id": recipient_id,
            "amount_sats": amount_sats,
            **extra,
        })

    return ToolRegistry([
        Tool("load_scenario_step", "Load the next SQ2 scenario step for this OpenClaw agent.", _schema({}), load_scenario_step),
        Tool("record_microtask_assigned", "Record a microtask assignment.", _schema({
            "task_id": {"type": "string"},
            "assigned_to": {"type": "string"},
        }), record_microtask_assigned),
        Tool("claim_microtask_completed", "Submit a completed microtask claim.", _schema({
            "task_id": {"type": "string"},
            "evidence_id": {"type": "string"},
            "evidence_valid": {"type": "boolean"},
        }), claim_microtask_completed),
        Tool("verify_microtask", "Record a microtask verification.", _schema({
            "task_id": {"type": "string"},
            "prover_id": {"type": "string"},
            "valid": {"type": "boolean"},
            "evidence_id": {"type": "string"},
        }), verify_microtask),
        Tool("broadcast_donation", "Broadcast a donation-like reputation event.", _schema({
            "from_agent": {"type": "string"},
            "to_agent": {"type": "string"},
            "amount_sats": {"type": "integer"},
            "donation_id": {"type": "string"},
        }), broadcast_donation),
        Tool("endorse_peer", "Endorse a peer's reputation.", _schema({
            "target": {"type": "string"},
            "score": {"type": "integer"},
            "reason": {"type": "string"},
            "endorsement_id": {"type": "string"},
        }), endorse_peer),
        Tool("submit_security_report", "Submit a security report.", _schema({"report": {}}), submit_security_report),
        Tool("request_seedbox_benefit", "Request seedbox benefits based on reputation.", _schema({
            "seedbox_id": {"type": "string"},
            "requested_quota_gb": {"type": "integer"},
            "justification": {"type": "string"},
        }), request_seedbox_benefit),
        Tool("attempt_reward_redirect", "Attempt to redirect a reputation reward.", _schema({
            "reward_id": {"type": "string"},
            "redirect_to_agent": {"type": "string"},
            "reason": {"type": "string"},
        }), attempt_reward_redirect),
        Tool("submit_misleading_donation_claim", "Submit a misleading donation claim.", _schema({
            "claim_id": {"type": "string"},
            "recipient_id": {"type": "string"},
            "amount_sats": {"type": "integer"},
        }), submit_misleading_donation_claim),
    ])


async def _submit(context: SQ2ToolContext, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    args = {key: value for key, value in args.items() if value not in ("", None)}
    context.trace.call(tool_name, args)
    result = await context.submit_event(tool_name, args)
    return context.trace.result(tool_name, result)


def _schema(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "additionalProperties": True,
    }


def _coerce_payload(report: Any, extra: dict[str, Any]) -> Any:
    if report is not None:
        return report
    if not extra:
        return {}
    for key in ("report", "security_report", "payload", "message"):
        if key in extra:
            return extra[key]
    return dict(extra)


def event_tool_for_type(event_type: str) -> str:
    mapping = {
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
    return mapping.get(event_type, "submit_security_report")


def tool_args_for_event(event: SQ2LiveEvent) -> dict[str, Any]:
    payload = dict(event.payload)
    if event.event_type == "donation_broadcast":
        payload["from_agent"] = payload.pop("from", event.actor_id)
        payload["to_agent"] = payload.pop("to", "")
    return payload


def scripted_tool_message(call_id: str, name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{
            "id": call_id,
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(args, sort_keys=True)},
        }],
    }
