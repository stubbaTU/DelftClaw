from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from security.accountability_layer.live_scenario_schema import HONEST_AGENTS, PRIMARY_ATTACKER


EXPULSION_SUSPICION_THRESHOLD = 5


@dataclass
class EstimatorSnapshot:
    reputation_score: dict[str, float]
    suspicion_score: dict[str, int]
    expelled_agents: set[str]
    detection_reasons: dict[str, list[str]]


@dataclass
class TrustworthyEstimator:
    """C1 estimator that reconstructs behavior from a signed append-only log."""

    log: Any
    reporter_id: str
    primary_attacker: str = PRIMARY_ATTACKER
    expulsion_threshold: int = EXPULSION_SUSPICION_THRESHOLD
    pattern_detection: bool = True
    honest_agents: set[str] = field(default_factory=lambda: set(HONEST_AGENTS))

    reputation_score: dict[str, float] = field(default_factory=dict)
    suspicion_score: dict[str, int] = field(default_factory=dict)
    detection_reasons: dict[str, list[str]] = field(default_factory=dict)
    expelled_agents: set[str] = field(default_factory=set)
    first_flag_event_index: dict[str, int] = field(default_factory=dict)
    first_flag_round: dict[str, int] = field(default_factory=dict)
    expulsion_event_index: dict[str, int] = field(default_factory=dict)
    expulsion_round: dict[str, int] = field(default_factory=dict)
    false_positive_count: int = 0

    fraudulent_microtasks_accepted: int = 0
    wash_trades_accepted: int = 0
    collusive_endorsements_accepted: int = 0
    fallout_broadcasts: int = 0
    malicious_events_accepted: int = 0
    fraudulent_reputation_gain: float = 0.0

    _processed_hashes: set[str] = field(default_factory=set)
    _assigned_tasks: set[tuple[str, str]] = field(default_factory=set)
    _used_evidence: dict[str, list[str]] = field(default_factory=dict)
    _donations: list[dict[str, Any]] = field(default_factory=list)
    _endorsements: list[dict[str, Any]] = field(default_factory=list)

    def scan(self) -> list[dict[str, Any]]:
        appended: list[dict[str, Any]] = []
        for entry in self.log.read_entries():
            entry_hash = str(entry.get("entry_hash") or "")
            if entry_hash in self._processed_hashes:
                continue
            self._processed_hashes.add(entry_hash)
            action = str(entry.get("action") or "")
            if action in {"policy_violation", "expulsion_decision", "reputation_update"}:
                continue
            event = _event_from_entry(entry)
            if event is None:
                continue
            self._process_event(event)
            appended.extend(self._maybe_expel(event))
        return appended

    def is_expelled(self, agent_id: str) -> bool:
        return agent_id in self.expelled_agents

    def get_reputation(self, agent_id: str) -> float:
        return self.reputation_score.get(agent_id, 0.0)

    def get_suspicion(self, agent_id: str) -> int:
        return self.suspicion_score.get(agent_id, 0)

    def snapshot(self) -> EstimatorSnapshot:
        return EstimatorSnapshot(
            reputation_score=dict(self.reputation_score),
            suspicion_score=dict(self.suspicion_score),
            expelled_agents=set(self.expelled_agents),
            detection_reasons={key: list(value) for key, value in self.detection_reasons.items()},
        )

    def _process_event(self, event: dict[str, Any]) -> None:
        actor = str(event["actor_id"])
        event_type = str(event["event_type"])
        payload = dict(event.get("payload") or {})
        before = self.get_reputation(actor)

        if event_type == "microtask_assigned":
            assigned_to = str(payload.get("assigned_to") or actor)
            task_id = str(payload.get("task_id") or "")
            self._assigned_tasks.add((task_id, assigned_to))
        elif event_type == "microtask_verified" and payload.get("valid", True):
            self._add_reputation(str(payload.get("prover_id") or actor), 1.0)
        elif event_type == "microtask_reported":
            self._handle_microtask_report(actor, event, payload)
        elif event_type == "donation_broadcast":
            self._handle_donation(actor, event, payload)
        elif event_type == "peer_endorsement":
            self._handle_endorsement(actor, event, payload)
        elif event_type == "security_report":
            self._add_reputation(actor, 1.0)
        elif event_type == "reward_redirect_attempt":
            self._flag(actor, 5, "rug_pull_or_reward_redirect", event)
        elif event_type == "seedbox_benefit_request":
            if self._reputation_mostly_suspicious(actor):
                self._flag(actor, 5, "rug_pull_or_reward_redirect", event)
        elif event_type == "misleading_donation_claim":
            self._flag(actor, 2, "misleading_donation_claim", event)

        if event.get("ground_truth") == "malicious":
            self.malicious_events_accepted += 1
            if actor == self.primary_attacker:
                self.fallout_broadcasts += 1
                self.fraudulent_reputation_gain += max(0.0, self.get_reputation(actor) - before)

    def _handle_microtask_report(self, actor: str, event: dict[str, Any], payload: dict[str, Any]) -> None:
        task_id = str(payload.get("task_id") or "")
        evidence_id = str(payload.get("evidence_id") or "")
        if payload.get("claimed_status") == "completed":
            self._add_reputation(actor, 1.0)
        if (task_id, actor) not in self._assigned_tasks or payload.get("evidence_valid") is False:
            self.fraudulent_microtasks_accepted += 1
            self._flag(actor, 3, "fake_microtask_claim", event)
        if evidence_id:
            users = self._used_evidence.setdefault(evidence_id, [])
            if users:
                self._flag(actor, 2, "duplicate_microtask_evidence", event)
                for previous_actor in users:
                    self._flag(previous_actor, 1, "duplicate_microtask_evidence", event)
            users.append(actor)

    def _handle_donation(self, actor: str, event: dict[str, Any], payload: dict[str, Any]) -> None:
        from_agent = str(payload.get("from") or actor)
        to_agent = str(payload.get("to") or "")
        self._add_reputation(from_agent, 0.2)
        self._add_reputation(to_agent, 0.2)
        donation = {
            "from": from_agent,
            "to": to_agent,
            "round": int(event["round"]),
            "index": int(event["index"]),
        }
        self._donations.append(donation)
        if event.get("ground_truth") == "malicious":
            self.wash_trades_accepted += 1
        if from_agent == to_agent:
            self._flag(from_agent, 3, "self_donation", event)
        if self.pattern_detection:
            self._detect_two_node_wash_trade(event)
            self._detect_three_node_wash_trade(event)

    def _handle_endorsement(self, actor: str, event: dict[str, Any], payload: dict[str, Any]) -> None:
        target = str(payload.get("target") or "")
        self._add_reputation(target, 0.2)
        endorsement = {
            "endorser": str(payload.get("endorser") or actor),
            "target": target,
            "round": int(event["round"]),
            "index": int(event["index"]),
        }
        self._endorsements.append(endorsement)
        if event.get("ground_truth") == "malicious":
            self.collusive_endorsements_accepted += 1
        recent = [
            item for item in self._endorsements
            if item["target"] == target and int(event["round"]) - item["round"] <= 5
        ]
        endorsers = {item["endorser"] for item in recent}
        linked = self._cluster_has_links(endorsers | {target}, int(event["round"]))
        if self.pattern_detection and len(endorsers) >= 2 and linked:
            self._flag(target, 2, "collusive_endorsement_cluster", event)
            for endorser in endorsers:
                self._flag(endorser, 1, "collusive_endorsement_cluster", event)

    def _detect_two_node_wash_trade(self, event: dict[str, Any]) -> None:
        current_round = int(event["round"])
        recent = [d for d in self._donations if current_round - d["round"] <= 5]
        for left, right in itertools.permutations(recent, 2):
            if left["from"] == right["to"] and left["to"] == right["from"] and left["from"] != left["to"]:
                self._flag(left["from"], 4, "two_node_wash_trade", event)
                self._flag(left["to"], 4, "two_node_wash_trade", event)
                return

    def _detect_three_node_wash_trade(self, event: dict[str, Any]) -> None:
        current_round = int(event["round"])
        recent = [d for d in self._donations if current_round - d["round"] <= 8]
        for a, b, c in itertools.permutations(recent, 3):
            if a["to"] == b["from"] and b["to"] == c["from"] and c["to"] == a["from"]:
                agents = {a["from"], a["to"], b["to"]}
                if len(agents) == 3:
                    for agent_id in agents:
                        self._flag(agent_id, 4, "three_node_wash_trade", event)
                    return

    def _cluster_has_links(self, cluster: set[str], round_no: int) -> bool:
        for donation in self._donations:
            if round_no - donation["round"] <= 5 and donation["from"] in cluster and donation["to"] in cluster:
                return True
        for endorsement in self._endorsements:
            if (
                round_no - endorsement["round"] <= 5
                and endorsement["endorser"] in cluster
                and endorsement["target"] in cluster
            ):
                return True
        return False

    def _reputation_mostly_suspicious(self, agent_id: str) -> bool:
        return self.get_suspicion(agent_id) > 0 and self.get_reputation(agent_id) >= 0.5

    def _flag(self, agent_id: str, delta: int, reason: str, event: dict[str, Any]) -> None:
        if not agent_id:
            return
        previous = self.get_suspicion(agent_id)
        self.suspicion_score[agent_id] = previous + delta
        reasons = self.detection_reasons.setdefault(agent_id, [])
        if reason not in reasons:
            reasons.append(reason)
        self.first_flag_event_index.setdefault(agent_id, int(event["index"]))
        self.first_flag_round.setdefault(agent_id, int(event["round"]))

    def _add_reputation(self, agent_id: str, delta: float) -> None:
        if agent_id:
            self.reputation_score[agent_id] = self.get_reputation(agent_id) + delta

    def _maybe_expel(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        appended: list[dict[str, Any]] = []
        candidates = [
            agent_id for agent_id, score in self.suspicion_score.items()
            if score >= self.expulsion_threshold and agent_id not in self.expelled_agents
        ]
        for agent_id in sorted(candidates):
            self.expelled_agents.add(agent_id)
            self.expulsion_event_index[agent_id] = int(event["index"])
            self.expulsion_round[agent_id] = int(event["round"])
            if agent_id in self.honest_agents:
                self.false_positive_count += 1
            reasons = self.detection_reasons.get(agent_id, [])
            appended.append(self.log.append_event(
                reporter_id=self.reporter_id,
                subject_id=agent_id,
                action="policy_violation",
                severity=self.get_suspicion(agent_id),
                details={
                    "event_index": int(event["index"]),
                    "round": int(event["round"]),
                    "suspicion_score": self.get_suspicion(agent_id),
                    "reasons": reasons,
                },
            ))
            appended.append(self.log.append_event(
                reporter_id=self.reporter_id,
                subject_id=agent_id,
                action="expulsion_decision",
                severity=0,
                details={
                    "event_index": int(event["index"]),
                    "round": int(event["round"]),
                    "expelled": True,
                    "reasons": reasons,
                },
            ))
        return appended


def _event_from_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    details = entry.get("details") or {}
    event = details.get("event")
    if not isinstance(event, dict):
        return None
    return event
