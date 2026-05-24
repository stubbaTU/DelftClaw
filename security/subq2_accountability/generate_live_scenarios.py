from __future__ import annotations

import argparse
import random
from pathlib import Path
from typing import Any

from security.subq2_accountability.live_scenario_schema import (
    ALL_AGENTS,
    DEFAULT_LIVE_SCENARIOS,
    HONEST_AGENTS,
    PRIMARY_ATTACKER,
    SYBIL_AGENTS,
    SQ2LiveEvent,
    SQ2LiveScenario,
    validate_scenarios,
    write_scenarios,
)


FAMILIES = [
    "R1_fake_microtask_claims",
    "R2_wash_trading_self_donation",
    "R3_collusive_endorsements",
    "R4_delayed_rug_pull",
]
INTENSITIES = ["low", "medium", "high"]
INTENSITY_COUNTS = {
    "low": 2,
    "medium": 4,
    "high": 6,
}


def generate_scenarios() -> list[SQ2LiveScenario]:
    scenarios: list[SQ2LiveScenario] = []
    for family in FAMILIES:
        for intensity in INTENSITIES:
            for seed in range(1, 6):
                scenarios.append(_build_scenario(family, intensity, seed))
    errors = validate_scenarios(scenarios)
    if errors:
        raise RuntimeError("generated invalid SQ2 scenarios: " + "; ".join(errors))
    return scenarios


def _build_scenario(family: str, intensity: str, seed: int) -> SQ2LiveScenario:
    rng = random.Random(f"{family}:{intensity}:{seed}")
    events: list[SQ2LiveEvent] = []

    def append(round_no: int, actor_id: str, event_type: str, payload: dict[str, Any], truth: str = "benign") -> None:
        index = len(events) + 1
        timestamp = f"2026-05-24T12:{round_no:02d}:{index % 60:02d}Z"
        events.append(SQ2LiveEvent(
            index=index,
            round=round_no,
            timestamp=timestamp,
            actor_id=actor_id,
            event_type=event_type,
            payload=payload,
            ground_truth=truth,
        ))

    # Stage 1: every run starts with mixed honest work and a believable M0 history.
    for round_no in range(1, 6):
        honest = HONEST_AGENTS[(round_no + seed) % len(HONEST_AGENTS)]
        task_id = f"{family}_{intensity}_{seed}_honest_{round_no}"
        append(round_no, honest, "microtask_assigned", {"task_id": task_id, "assigned_to": honest})
        append(round_no, honest, "microtask_verified", {
            "task_id": task_id,
            "prover_id": honest,
            "valid": True,
            "evidence_id": f"ev_{task_id}",
        })
        if round_no in {2, 4}:
            m_task = f"{family}_{intensity}_{seed}_m0_warmup_{round_no}"
            append(round_no, PRIMARY_ATTACKER, "microtask_verified", {
                "task_id": m_task,
                "prover_id": PRIMARY_ATTACKER,
                "valid": True,
                "evidence_id": f"ev_{m_task}",
            })

    malicious_count = INTENSITY_COUNTS[intensity]

    if family == "R1_fake_microtask_claims":
        _append_fake_microtasks(append, family, intensity, seed, malicious_count)
    elif family == "R2_wash_trading_self_donation":
        _append_wash_trading(append, family, intensity, seed, malicious_count)
    elif family == "R3_collusive_endorsements":
        _append_collusion(append, family, intensity, seed, malicious_count, rng)
    elif family == "R4_delayed_rug_pull":
        _append_delayed_rug_pull(append, family, intensity, seed, malicious_count)
    else:
        raise ValueError(f"unknown family {family}")

    first_malicious = next(event for event in events if event.malicious)
    first_malicious_event_index = first_malicious.index
    first_malicious_round = first_malicious.round
    defection_event_index = len(events) + 1
    defection_round = max(events[-1].round + 1, 12)
    append(defection_round, PRIMARY_ATTACKER, "seedbox_benefit_request", {
        "seedbox_id": f"benefit_{family}_{intensity}_{seed}",
        "requested_quota_gb": 500 + malicious_count * 100,
        "justification": "high reputation operator requesting premium swarm allocation",
    }, "malicious")
    append(defection_round + 1, PRIMARY_ATTACKER, "reward_redirect_attempt", {
        "reward_id": f"reward_{family}_{intensity}_{seed}",
        "redirect_to_agent": SYBIL_AGENTS[seed % len(SYBIL_AGENTS)],
        "reason": "operator-maintenance reward reroute",
    }, "malicious")

    # Keep a few post-defection events so lag/fallout is meaningful if C0 does not expel.
    for i in range(2):
        append(defection_round + 2 + i, PRIMARY_ATTACKER, "misleading_donation_claim", {
            "claim_id": f"mislead_{family}_{intensity}_{seed}_{i}",
            "recipient_id": PRIMARY_ATTACKER,
            "amount_sats": 10_000 + i,
        }, "malicious")

    scenario_id = f"{family}_{intensity}_seed{seed:02d}"
    return SQ2LiveScenario(
        scenario_id=scenario_id,
        family=family,
        intensity=intensity,
        seed=seed,
        num_honest_agents=len(HONEST_AGENTS),
        malicious_agents=[PRIMARY_ATTACKER, *SYBIL_AGENTS],
        primary_attacker=PRIMARY_ATTACKER,
        first_malicious_event_index=first_malicious_event_index,
        first_malicious_round=first_malicious_round,
        defection_event_index=defection_event_index,
        defection_round=defection_round,
        events=events,
    )


def _append_fake_microtasks(append: Any, family: str, intensity: str, seed: int, count: int) -> None:
    evidence_pool = [f"replayed_evidence_{seed}", f"replayed_evidence_{seed}"]
    for i in range(count):
        round_no = 6 + i
        evidence_id = evidence_pool[i % len(evidence_pool)] if i < 3 else f"fake_evidence_{seed}_{i}"
        append(round_no, PRIMARY_ATTACKER, "microtask_reported", {
            "task_id": f"unassigned_task_{family}_{intensity}_{seed}_{i}",
            "claimed_status": "completed",
            "evidence_valid": i % 2 == 0,
            "evidence_id": evidence_id,
        }, "malicious")


def _append_wash_trading(append: Any, family: str, intensity: str, seed: int, count: int) -> None:
    cycle = [(PRIMARY_ATTACKER, "S1"), ("S1", PRIMARY_ATTACKER), (PRIMARY_ATTACKER, "S2"), ("S2", "S1"), ("S1", PRIMARY_ATTACKER)]
    for i in range(count):
        from_agent, to_agent = cycle[i % len(cycle)]
        if intensity == "high" and i == count - 1:
            from_agent = to_agent = PRIMARY_ATTACKER
        append(6 + i, from_agent, "donation_broadcast", {
            "donation_id": f"wash_{family}_{intensity}_{seed}_{i}",
            "from": from_agent,
            "to": to_agent,
            "amount_sats": 2000 + i * 25,
            "seedbox_id": f"sq2_seedbox_{seed}",
        }, "malicious")


def _append_collusion(append: Any, family: str, intensity: str, seed: int, count: int, rng: random.Random) -> None:
    endorsers = [*SYBIL_AGENTS, PRIMARY_ATTACKER]
    for i in range(count):
        endorser = endorsers[i % len(endorsers)]
        target = PRIMARY_ATTACKER if endorser != PRIMARY_ATTACKER else rng.choice(SYBIL_AGENTS)
        append(6 + i, endorser, "peer_endorsement", {
            "endorsement_id": f"endorse_{family}_{intensity}_{seed}_{i}",
            "endorser": endorser,
            "target": target,
            "score": 1,
            "reason": "operator reliability observed during swarm maintenance",
        }, "malicious")
        if i in {1, 3}:
            append(6 + i, endorser, "donation_broadcast", {
                "donation_id": f"collusive_link_{family}_{intensity}_{seed}_{i}",
                "from": endorser,
                "to": target,
                "amount_sats": 1000 + i,
                "seedbox_id": f"sq2_collusion_{seed}",
            }, "malicious")


def _append_delayed_rug_pull(append: Any, family: str, intensity: str, seed: int, count: int) -> None:
    for i in range(max(1, count // 2)):
        append(6 + i, PRIMARY_ATTACKER, "microtask_verified", {
            "task_id": f"m0_legit_late_{family}_{intensity}_{seed}_{i}",
            "prover_id": PRIMARY_ATTACKER,
            "valid": True,
            "evidence_id": f"ev_m0_legit_late_{seed}_{i}",
        })
    start = 6 + max(1, count // 2)
    for i in range(count):
        actor = SYBIL_AGENTS[i % len(SYBIL_AGENTS)]
        append(start + i, actor, "peer_endorsement", {
            "endorsement_id": f"delayed_endorse_{family}_{intensity}_{seed}_{i}",
            "endorser": actor,
            "target": PRIMARY_ATTACKER,
            "score": 1,
            "reason": "long-running trusted seedbox operator",
        }, "malicious")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate frozen SQ2 live reputation-trap scenarios.")
    parser.add_argument("--out", type=Path, default=DEFAULT_LIVE_SCENARIOS)
    args = parser.parse_args()
    scenarios = generate_scenarios()
    write_scenarios(args.out, scenarios)
    print(f"wrote {len(scenarios)} scenarios to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
