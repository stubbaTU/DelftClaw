from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from security.accountability_layer.infrastructure.live_scenario_schema import HONEST_AGENTS, PRIMARY_ATTACKER, SQ2LiveEvent


@dataclass
class NaiveEventDecision:
    accepted: bool
    blocked: bool = False
    expelled_now: bool = False
    reason: str = ""


@dataclass
class NaiveReputationState:
    """Mutable C0 reputation state with deliberately weak accountability."""

    primary_attacker: str = PRIMARY_ATTACKER
    direct_defection_threshold: int = 5
    honest_agents: set[str] = field(default_factory=lambda: set(HONEST_AGENTS))
    reputation_score: dict[str, float] = field(default_factory=dict)
    expelled_agents: set[str] = field(default_factory=set)
    direct_defection_count: dict[str, int] = field(default_factory=dict)
    expulsion_event_index: dict[str, int] = field(default_factory=dict)
    expulsion_round: dict[str, int] = field(default_factory=dict)
    false_positive_count: int = 0

    fraudulent_microtasks_accepted: int = 0
    wash_trades_accepted: int = 0
    collusive_endorsements_accepted: int = 0
    fallout_broadcasts: int = 0
    malicious_events_accepted: int = 0
    fraudulent_reputation_gain: float = 0.0

    def process_event(self, event: SQ2LiveEvent) -> NaiveEventDecision:
        # accepts essentially everything, applies reputation by blindly trusting claims, and onl expels after 5 direct defections
        actor = event.actor_id
        if actor in self.expelled_agents:
            return NaiveEventDecision(accepted=False, blocked=True, reason="actor already expelled")

        before = self.get_reputation(actor)
        self._apply_reputation(event)
        after = self.get_reputation(actor)

        if event.malicious:
            self.malicious_events_accepted += 1
            if actor == self.primary_attacker:
                self.fallout_broadcasts += 1
                self.fraudulent_reputation_gain += max(0.0, after - before)
            if event.event_type == "microtask_reported":
                self.fraudulent_microtasks_accepted += 1
            if event.event_type == "donation_broadcast":
                self.wash_trades_accepted += 1
            if event.event_type == "peer_endorsement":
                self.collusive_endorsements_accepted += 1

        expelled_now = False
        if event.event_type in {"reward_redirect_attempt", "misleading_donation_claim"}:
            count = self.direct_defection_count.get(actor, 0) + 1
            self.direct_defection_count[actor] = count
            if count >= self.direct_defection_threshold:
                expelled_now = self._expel(actor, event)

        return NaiveEventDecision(
            accepted=True,
            expelled_now=expelled_now,
            reason="accepted by naive mutable reputation state",
        )

    def get_reputation(self, agent_id: str) -> float:
        return self.reputation_score.get(agent_id, 0.0)

    def is_expelled(self, agent_id: str) -> bool:
        return agent_id in self.expelled_agents

    def _apply_reputation(self, event: SQ2LiveEvent) -> None:
        actor = event.actor_id
        payload = event.payload
        if event.event_type == "microtask_reported" and payload.get("claimed_status") == "completed":
            self._add(actor, 1.0)
        elif event.event_type == "microtask_verified" and payload.get("valid", True):
            self._add(str(payload.get("prover_id") or actor), 1.0)
        elif event.event_type == "donation_broadcast":
            self._add(actor, 1.0)
            recipient = str(payload.get("to") or "")
            if recipient:
                self._add(recipient, 0.5)
        elif event.event_type == "peer_endorsement":
            target = str(payload.get("target") or actor)
            self._add(target, 1.0)
        elif event.event_type == "security_report":
            self._add(actor, 0.5)

    def _add(self, agent_id: str, delta: float) -> None:
        self.reputation_score[agent_id] = self.get_reputation(agent_id) + delta

    def _expel(self, agent_id: str, event: SQ2LiveEvent) -> bool:
        if agent_id in self.expelled_agents:
            return False
        self.expelled_agents.add(agent_id)
        self.expulsion_event_index[agent_id] = event.index
        self.expulsion_round[agent_id] = event.round
        if agent_id in self.honest_agents:
            self.false_positive_count += 1
        return True
