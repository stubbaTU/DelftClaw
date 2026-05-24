from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_LIVE_SCENARIOS = Path("security/datasets/sq2_live_reputation_trap_scenarios.jsonl")

HONEST_AGENTS = [f"H{i}" for i in range(8)]
PRIMARY_ATTACKER = "M0"
SYBIL_AGENTS = ["S1", "S2"]
ALL_AGENTS = HONEST_AGENTS + [PRIMARY_ATTACKER] + SYBIL_AGENTS

CONDITION_C0 = "C0_no_accountability"
CONDITION_C1 = "C1_tamper_evident_accountability"

EVENT_TYPES = {
    "microtask_assigned",
    "microtask_reported",
    "microtask_verified",
    "donation_broadcast",
    "peer_endorsement",
    "security_report",
    "reputation_update",
    "policy_violation",
    "expulsion_decision",
    "seedbox_benefit_request",
    "reward_redirect_attempt",
    "misleading_donation_claim",
}


@dataclass(frozen=True)
class SQ2LiveEvent:
    index: int
    round: int
    timestamp: str
    actor_id: str
    event_type: str
    payload: dict[str, Any]
    ground_truth: str = "benign"

    @property
    def malicious(self) -> bool:
        return self.ground_truth == "malicious"


@dataclass(frozen=True)
class SQ2LiveScenario:
    scenario_id: str
    family: str
    intensity: str
    seed: int
    num_honest_agents: int
    malicious_agents: list[str]
    primary_attacker: str
    first_malicious_event_index: int
    first_malicious_round: int
    defection_event_index: int
    defection_round: int
    events: list[SQ2LiveEvent] = field(default_factory=list)


def scenario_to_dict(scenario: SQ2LiveScenario) -> dict[str, Any]:
    return asdict(scenario)


def scenario_from_dict(raw: dict[str, Any]) -> SQ2LiveScenario:
    events = [
        event if isinstance(event, SQ2LiveEvent) else SQ2LiveEvent(**event)
        for event in raw.get("events", [])
    ]
    data = dict(raw)
    data["events"] = events
    return SQ2LiveScenario(**data)


def load_scenarios(path: str | Path = DEFAULT_LIVE_SCENARIOS) -> list[SQ2LiveScenario]:
    scenarios: list[SQ2LiveScenario] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            scenarios.append(scenario_from_dict(json.loads(line)))
    errors = validate_scenarios(scenarios)
    if errors:
        raise ValueError("invalid SQ2 live scenario corpus: " + "; ".join(errors))
    return scenarios


def write_scenarios(path: str | Path, scenarios: list[SQ2LiveScenario]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for scenario in scenarios:
            handle.write(json.dumps(scenario_to_dict(scenario), sort_keys=True) + "\n")


def validate_scenarios(scenarios: list[SQ2LiveScenario]) -> list[str]:
    errors: list[str] = []
    seen_ids: set[str] = set()
    for scenario in scenarios:
        if scenario.scenario_id in seen_ids:
            errors.append(f"duplicate scenario_id {scenario.scenario_id}")
        seen_ids.add(scenario.scenario_id)
        if scenario.primary_attacker not in scenario.malicious_agents:
            errors.append(f"{scenario.scenario_id}: primary attacker not in malicious_agents")
        if scenario.primary_attacker != PRIMARY_ATTACKER:
            errors.append(f"{scenario.scenario_id}: expected primary attacker {PRIMARY_ATTACKER}")
        event_indices = [event.index for event in scenario.events]
        if event_indices != list(range(1, len(scenario.events) + 1)):
            errors.append(f"{scenario.scenario_id}: event indices must be contiguous and 1-based")
        for event in scenario.events:
            if event.event_type not in EVENT_TYPES:
                errors.append(f"{scenario.scenario_id}: unknown event_type {event.event_type}")
            if event.actor_id not in ALL_AGENTS:
                errors.append(f"{scenario.scenario_id}: unknown actor_id {event.actor_id}")
            if event.ground_truth not in {"benign", "malicious"}:
                errors.append(f"{scenario.scenario_id}: invalid ground_truth {event.ground_truth}")
        malicious_events = [event for event in scenario.events if event.malicious]
        if not malicious_events:
            errors.append(f"{scenario.scenario_id}: no malicious events")
        else:
            first = malicious_events[0]
            if scenario.first_malicious_event_index != first.index:
                errors.append(f"{scenario.scenario_id}: first_malicious_event_index mismatch")
            if scenario.first_malicious_round != first.round:
                errors.append(f"{scenario.scenario_id}: first_malicious_round mismatch")
    return errors


def sanitized_event_for_agent(event: SQ2LiveEvent) -> dict[str, Any]:
    """Return event instructions without evaluator-only labels."""
    return {
        "index": event.index,
        "round": event.round,
        "timestamp": event.timestamp,
        "actor_id": event.actor_id,
        "event_type": event.event_type,
        "payload": event.payload,
    }

