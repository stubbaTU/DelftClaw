"""
LEGACY
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class BetaReputationEstimator:
    """Simple literature-style Beta reputation baseline over recorded events."""

    trust_cutoff: float = 0.35
    min_observations: int = 2
    alpha: dict[str, float] = field(default_factory=dict)
    beta: dict[str, float] = field(default_factory=dict)
    expelled_agents: set[str] = field(default_factory=set)
    expulsion_event_index: dict[str, int] = field(default_factory=dict)

    def process(self, event: dict[str, Any]) -> None:
        actor = str(event["actor_id"])
        event_type = str(event["event_type"])
        payload = dict(event.get("payload") or {})
        success, failure = 0.0, 0.0
        if event_type in {"microtask_verified", "security_report"} and payload.get("valid", True):
            success = 1.0
        elif event_type == "microtask_reported" and (
            payload.get("evidence_valid") is False or str(payload.get("task_id", "")).startswith("unassigned")
        ):
            failure = 1.0
        elif event_type in {"reward_redirect_attempt", "misleading_donation_claim"}:
            failure = 1.0
        elif event_type == "donation_broadcast" and payload.get("from") == payload.get("to"):
            failure = 1.0
        if not success and not failure:
            return
        self.alpha[actor] = self.alpha.get(actor, 1.0) + success
        self.beta[actor] = self.beta.get(actor, 1.0) + failure
        observations = self.alpha[actor] + self.beta[actor] - 2.0
        if observations >= self.min_observations and self.score(actor) < self.trust_cutoff:
            self.expelled_agents.add(actor)
            self.expulsion_event_index.setdefault(actor, int(event["index"]))

    def score(self, agent_id: str) -> float:
        alpha = self.alpha.get(agent_id, 1.0)
        beta = self.beta.get(agent_id, 1.0)
        return alpha / (alpha + beta)
