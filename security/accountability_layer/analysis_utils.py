from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable

from security.accountability_layer.live_scenario_schema import (
    CONDITION_B1,
    CONDITION_B2,
    CONDITION_C1,
    SQ2LiveScenario,
    load_scenarios,
)
from security.accountability_layer.mutable_log import ReplayLog
from security.accountability_layer.trustworthy_estimator import TrustworthyEstimator


def read_log_entries(path: str | Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("==="):
            continue
        value = json.loads(line)
        if isinstance(value, dict):
            entries.append(value)
    return entries


def scenario_replay_entries(scenario: SQ2LiveScenario) -> list[dict[str, Any]]:
    """Build complete counterfactual replay entries from the frozen scenario.

    Live C1 logs stop receiving an actor's events after expulsion. Threshold
    sweeps therefore use the complete deterministic scenario stream so a
    threshold above the original operating point is not evaluated on truncated
    history.
    """
    return [
        {
            "entry_hash": f"scenario-event-{event.index}",
            "action": event.event_type,
            "details": {"event": {
                "index": event.index,
                "round": event.round,
                "actor_id": event.actor_id,
                "event_type": event.event_type,
                "payload": dict(event.payload),
            }},
        }
        for event in scenario.events
    ]


def rescore_entries(
    entries: list[dict[str, Any]],
    scenario: SQ2LiveScenario,
    *,
    condition: str,
    threshold: int,
) -> dict[str, Any]:
    pattern_detection = condition != CONDITION_B2
    estimator = TrustworthyEstimator(
        log=ReplayLog(entries),
        reporter_id="post-hoc-rescorer",
        primary_attacker=scenario.primary_attacker,
        expulsion_threshold=threshold,
        pattern_detection=pattern_detection,
        honest_agents=set(scenario.honest_agents),
    )
    estimator.scan()
    primary = scenario.primary_attacker
    expulsion_event = estimator.expulsion_event_index.get(primary)
    expulsion_round = estimator.expulsion_round.get(primary)
    detected = expulsion_event is not None
    end_event = scenario.events[-1].index
    end_round = scenario.events[-1].round
    false_positives = sorted(estimator.expelled_agents.intersection(scenario.honest_agents))
    fallout = _counterfactual_fallout(scenario, estimator.expulsion_event_index)
    return {
        "scenario_id": scenario.scenario_id,
        "family": scenario.family,
        "intensity": scenario.intensity,
        "seed": scenario.seed,
        "attacker_strategy": scenario.attacker_strategy,
        "condition": condition,
        "pattern_detection": pattern_detection,
        "signed_log": condition != CONDITION_B1,
        "threshold": threshold,
        "expelled": detected,
        "censored": not detected,
        "expulsion_event_index": expulsion_event,
        "expulsion_round": expulsion_round,
        "reputation_lag_events": (
            int(expulsion_event) - scenario.first_malicious_event_index
            if detected else end_event - scenario.first_malicious_event_index
        ),
        "reputation_lag_rounds": (
            int(expulsion_round) - scenario.first_malicious_round
            if detected else end_round - scenario.first_malicious_round
        ),
        "final_attacker_suspicion": estimator.get_suspicion(primary),
        "detection_reasons": ",".join(estimator.detection_reasons.get(primary, [])),
        "false_positive_count": len(false_positives),
        "false_positive_rate": len(false_positives) / len(scenario.honest_agents),
        "honest_agent_count": len(scenario.honest_agents),
        "false_positive_agents": ",".join(false_positives),
        **fallout,
    }


def discover_c1_logs(run_dir: str | Path) -> list[tuple[SQ2LiveScenario, Path]]:
    root = Path(run_dir)
    scenario_path = root / "sq2_scenarios.jsonl"
    scenarios = {scenario.scenario_id: scenario for scenario in load_scenarios(scenario_path)}
    condition_dir = root / "trials" / CONDITION_C1
    found: list[tuple[SQ2LiveScenario, Path]] = []
    for scenario_id, scenario in scenarios.items():
        log_path = condition_dir / scenario_id / "accountability.log"
        if log_path.exists():
            found.append((scenario, log_path))
    return found


def write_rows(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    values = list(rows)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in values for key in row})
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(values)


def aggregate_rescores(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    keys = sorted({(row["condition"], row["attacker_strategy"], row["threshold"]) for row in rows})
    for condition, strategy, threshold in keys:
        group = [
            row for row in rows
            if row["condition"] == condition
            and row["attacker_strategy"] == strategy
            and row["threshold"] == threshold
        ]
        detected = [row for row in group if row["expelled"]]
        output.append({
            "condition": condition,
            "attacker_strategy": strategy,
            "threshold": threshold,
            "trials": len(group),
            "detected": len(detected),
            "detection_rate": len(detected) / len(group),
            "median_detected_lag_events": _median([row["reputation_lag_events"] for row in detected]),
            "false_positive_rate": sum(row["false_positive_count"] for row in group)
            / sum(row["honest_agent_count"] for row in group),
            "mean_fallout_broadcasts": _mean([row["fallout_broadcasts"] for row in group]),
            "mean_fraudulent_microtasks_accepted": _mean(
                [row["fraudulent_microtasks_accepted"] for row in group]
            ),
            "mean_wash_trades_accepted": _mean([row["wash_trades_accepted"] for row in group]),
            "mean_collusive_endorsements_accepted": _mean(
                [row["collusive_endorsements_accepted"] for row in group]
            ),
            "mean_fraudulent_reputation_gain": _mean(
                [row["fraudulent_reputation_gain"] for row in group]
            ),
        })
    return output


def _counterfactual_fallout(
    scenario: SQ2LiveScenario,
    expulsion_event_index: dict[str, int],
) -> dict[str, int | float]:
    """Measure effects occurring before each counterfactual expulsion boundary."""
    primary_cutoff = expulsion_event_index.get(scenario.primary_attacker, float("inf"))
    accepted = [
        event
        for event in scenario.events
        if event.malicious and event.index <= expulsion_event_index.get(event.actor_id, float("inf"))
    ]
    fallout_events = [event for event in accepted if event.index <= primary_cutoff]
    return {
        "fallout_broadcasts": len(fallout_events),
        "fraudulent_microtasks_accepted": sum(
            event.event_type == "microtask_reported" for event in accepted
        ),
        "wash_trades_accepted": sum(event.event_type == "donation_broadcast" for event in accepted),
        "collusive_endorsements_accepted": sum(
            event.event_type == "peer_endorsement" for event in accepted
        ),
        "fraudulent_reputation_gain": sum(
            _primary_reputation_gain(event, scenario.primary_attacker) for event in fallout_events
        ),
    }


def _primary_reputation_gain(event: Any, primary: str) -> float:
    payload = event.payload
    if event.event_type == "microtask_reported" and event.actor_id == primary:
        return 1.0 if payload.get("claimed_status") == "completed" else 0.0
    if event.event_type == "microtask_verified" and payload.get("valid", True):
        return 1.0 if str(payload.get("prover_id") or event.actor_id) == primary else 0.0
    if event.event_type == "donation_broadcast":
        gain = 0.0
        gain += 0.2 if str(payload.get("from") or event.actor_id) == primary else 0.0
        gain += 0.2 if str(payload.get("to") or "") == primary else 0.0
        return gain
    if event.event_type == "peer_endorsement":
        return 0.2 if str(payload.get("target") or "") == primary else 0.0
    return 0.0


def _mean(values: list[int | float]) -> float:
    return float(sum(values) / len(values)) if values else 0.0


def _median(values: list[int | float]) -> float | None:
    if not values:
        return None
    values = sorted(values)
    middle = len(values) // 2
    if len(values) % 2:
        return float(values[middle])
    return float((values[middle - 1] + values[middle]) / 2)
