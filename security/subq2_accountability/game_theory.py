from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class AttackPayoffModel:
    """Simple repeated-game model for fake seedbox accountability.

    A malicious agent compares immediate gain from fake/self donations against
    the discounted future value lost after expulsion. Deterrence holds when
    expected_attack_payoff <= expected_honest_payoff.
    """

    donation_gain: float = 1.0
    honest_round_value: float = 0.25
    detection_probability: float = 1.0
    discount_factor: float = 0.95
    expulsion_penalty_rounds: int = 20
    false_positive_cost: float = 0.0

    def expected_honest_payoff(self, rounds: int) -> float:
        return sum((self.discount_factor ** i) * self.honest_round_value for i in range(rounds))

    def expected_attack_payoff(self, accepted_malicious_actions: int) -> float:
        immediate_gain = accepted_malicious_actions * self.donation_gain
        future_loss = self.detection_probability * self.expected_honest_payoff(self.expulsion_penalty_rounds)
        return immediate_gain - future_loss - self.false_positive_cost

    def deterrence_margin(self, accepted_malicious_actions: int) -> float:
        return self.expected_honest_payoff(accepted_malicious_actions) - self.expected_attack_payoff(
            accepted_malicious_actions
        )

    def is_deterred(self, accepted_malicious_actions: int) -> bool:
        return self.deterrence_margin(accepted_malicious_actions) >= 0


@dataclass(frozen=True)
class ReputationPolicy:
    ban_threshold: int
    scan_interval: int
    malicious_action_weight: int
    proof_missing_weight: int = 10

    def accepted_actions_before_expulsion(self) -> int:
        if self.malicious_action_weight <= 0:
            return 10**9
        return max(1, (self.ban_threshold + self.malicious_action_weight - 1) // self.malicious_action_weight)

    def expected_blast_radius(self) -> int:
        accepted = self.accepted_actions_before_expulsion()
        if self.scan_interval <= 1:
            return accepted
        return accepted + self.scan_interval - 1


def sweep_reputation_policies(
    *,
    thresholds: list[int],
    scan_intervals: list[int],
    malicious_action_weight: int,
    payoff_model: AttackPayoffModel | None = None,
) -> list[dict[str, Any]]:
    model = payoff_model or AttackPayoffModel()
    rows = []
    for threshold in thresholds:
        for scan_interval in scan_intervals:
            policy = ReputationPolicy(
                ban_threshold=threshold,
                scan_interval=scan_interval,
                malicious_action_weight=malicious_action_weight,
            )
            blast_radius = policy.expected_blast_radius()
            rows.append(
                {
                    **asdict(policy),
                    "expected_blast_radius": blast_radius,
                    "attack_payoff": model.expected_attack_payoff(blast_radius),
                    "honest_payoff": model.expected_honest_payoff(blast_radius),
                    "deterrence_margin": model.deterrence_margin(blast_radius),
                    "deterred": model.is_deterred(blast_radius),
                }
            )
    return rows
