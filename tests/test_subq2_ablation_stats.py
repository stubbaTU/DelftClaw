from __future__ import annotations

import asyncio
import json
from pathlib import Path

from security.accountability_layer.evaluation.analysis_utils import (
    aggregate_rescores,
    discover_c1_logs,
    read_log_entries,
    rescore_entries,
)
from security.accountability_layer.evaluation.generate_live_scenarios import generate_scenarios
from security.accountability_layer.evaluation.live_orchestrator import run_live_measurement
from security.accountability_layer.infrastructure.live_scenario_schema import (
    CONDITION_B1,
    CONDITION_B2,
    CONDITION_C1,
    write_scenarios,
)
from security.accountability_layer.infrastructure.mutable_log import ReplayLog
from security.accountability_layer.evaluation.sweep_thresholds import sweep
from security.accountability_layer.infrastructure.trustworthy_estimator import TrustworthyEstimator


def _entry(index: int, actor: str, event_type: str, payload: dict) -> dict:
    return {
        "entry_hash": f"event-{index}",
        "action": event_type,
        "details": {"event": {
            "index": index,
            "round": index,
            "actor_id": actor,
            "event_type": event_type,
            "payload": payload,
        }},
    }


def test_pattern_ablation_removes_cross_agent_reconstruction() -> None:
    entries = [
        _entry(1, "M0", "donation_broadcast", {"from": "M0", "to": "S1"}),
        _entry(2, "S1", "donation_broadcast", {"from": "S1", "to": "M0"}),
    ]
    full = TrustworthyEstimator(ReplayLog(entries), "r", expulsion_threshold=4, pattern_detection=True)
    ablated = TrustworthyEstimator(ReplayLog(entries), "r", expulsion_threshold=4, pattern_detection=False)

    full.scan()
    ablated.scan()

    assert full.is_expelled("M0")
    assert not ablated.is_expelled("M0")


def test_adaptive_metadata_and_honest_labels_do_not_leak() -> None:
    scenario = generate_scenarios(seeds_per_cell=1, attacker_strategy="threshold_aware")[0]
    visible = json.dumps([
        {
            "index": event.index,
            "round": event.round,
            "actor_id": event.actor_id,
            "event_type": event.event_type,
            "payload": event.payload,
            "instruction": event.instruction,
        }
        for event in scenario.events
    ])
    assert scenario.attacker_strategy == "threshold_aware"
    assert "threshold_aware" not in scenario.scenario_id
    assert "attacker_strategy" not in visible
    assert "ground_truth" not in visible
    assert "honest_agents" not in visible


def test_threshold_aware_strategy_creates_a_detection_boundary(tmp_path: Path) -> None:
    scenarios_path = tmp_path / "adaptive.jsonl"
    write_scenarios(
        scenarios_path,
        generate_scenarios(
            seeds_per_cell=1,
            attacker_strategy="threshold_aware",
            intensities=["medium", "high"],
        ),
    )
    out = tmp_path / "run"
    asyncio.run(run_live_measurement(
        scenarios_path=scenarios_path,
        export_dir=out,
        conditions=[CONDITION_C1],
        mode="deterministic",
        base_url="",
        model="",
        api_key="",
        temperature=0,
        max_iterations=4,
        estimator_interval=1,
        expulsion_threshold=5,
    ))
    rows = [
        json.loads(line) for line in (out / "sq2_trials.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(not row["expelled"] for row in rows)


def test_sybil_split_attributes_pattern_detection_gain(tmp_path: Path) -> None:
    scenarios_path = tmp_path / "sybil.jsonl"
    scenarios = [
        scenario
        for scenario in generate_scenarios(
            seeds_per_cell=1,
            attacker_strategy="sybil_split",
            intensities=["medium", "high"],
        )
        if scenario.family in {"R2_wash_trading_self_donation", "R3_collusive_endorsements"}
    ]
    write_scenarios(scenarios_path, scenarios)
    out = tmp_path / "run"
    asyncio.run(run_live_measurement(
        scenarios_path=scenarios_path,
        export_dir=out,
        conditions=[CONDITION_B2, CONDITION_C1],
        mode="deterministic",
        base_url="",
        model="",
        api_key="",
        temperature=0,
        max_iterations=4,
        estimator_interval=1,
        expulsion_threshold=5,
    ))
    rows = [
        json.loads(line) for line in (out / "sq2_trials.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    b2_detected = sum(row["expelled"] for row in rows if row["condition"] == CONDITION_B2)
    c1_detected = sum(row["expelled"] for row in rows if row["condition"] == CONDITION_C1)
    assert b2_detected < c1_detected


def test_factorial_conditions_and_tamper_measurement(tmp_path: Path) -> None:
    scenarios_path = tmp_path / "scenarios.jsonl"
    write_scenarios(scenarios_path, generate_scenarios(seeds_per_cell=1))
    normal = tmp_path / "normal"
    tamper = tmp_path / "tamper"

    asyncio.run(run_live_measurement(
        scenarios_path=scenarios_path,
        export_dir=normal,
        conditions=[CONDITION_B1, CONDITION_B2, CONDITION_C1],
        mode="deterministic",
        base_url="",
        model="",
        api_key="",
        temperature=0,
        max_iterations=4,
        estimator_interval=1,
        expulsion_threshold=5,
        limit=1,
    ))
    asyncio.run(run_live_measurement(
        scenarios_path=scenarios_path,
        export_dir=tamper,
        conditions=[CONDITION_B1, CONDITION_C1],
        mode="deterministic",
        base_url="",
        model="",
        api_key="",
        temperature=0,
        max_iterations=4,
        estimator_interval=1,
        expulsion_threshold=5,
        limit=1,
        inject_tamper=True,
    ))

    normal_rows = [
        json.loads(line) for line in (normal / "sq2_trials.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert {row["condition"] for row in normal_rows} == {CONDITION_B1, CONDITION_B2, CONDITION_C1}
    integrity = (tamper / "sq2_log_integrity.csv").read_text(encoding="utf-8")
    assert "tamper_suppressed_history" in integrity
    assert "True" in integrity


def test_rescore_reproduces_c1_and_low_threshold_has_real_false_positives(tmp_path: Path) -> None:
    scenarios_path = tmp_path / "adaptive.jsonl"
    scenarios = generate_scenarios(seeds_per_cell=1, attacker_strategy="threshold_aware")
    write_scenarios(scenarios_path, scenarios)
    out = tmp_path / "run"
    asyncio.run(run_live_measurement(
        scenarios_path=scenarios_path,
        export_dir=out,
        conditions=[CONDITION_C1],
        mode="deterministic",
        base_url="",
        model="",
        api_key="",
        temperature=0,
        max_iterations=4,
        estimator_interval=1,
        expulsion_threshold=5,
        limit=1,
    ))
    scenario = scenarios[0]
    entries = read_log_entries(out / "trials" / CONDITION_C1 / scenario.scenario_id / "accountability.log")
    signed_text = (out / "trials" / CONDITION_C1 / scenario.scenario_id / "accountability.log").read_text(
        encoding="utf-8"
    )
    original = json.loads((out / "sq2_trials.jsonl").read_text(encoding="utf-8").splitlines()[0])
    replay = rescore_entries(entries, scenario, condition=CONDITION_C1, threshold=5)
    low = rescore_entries(entries, scenario, condition=CONDITION_C1, threshold=1)

    assert replay["expelled"] == original["expelled"]
    assert replay["expulsion_event_index"] == original["expulsion_event_index"]
    assert low["false_positive_count"] > 0
    aggregates = aggregate_rescores([replay, low])
    assert "mean_fallout_broadcasts" in aggregates[0]
    assert "threshold_aware" not in signed_text
    assert "attacker_strategy" not in signed_text


def test_threshold_sweep_exports_frontiers_and_operating_point(tmp_path: Path) -> None:
    scenarios_path = tmp_path / "adaptive.jsonl"
    scenarios = generate_scenarios(seeds_per_cell=1, attacker_strategy="threshold_aware")
    write_scenarios(scenarios_path, scenarios)
    run_dir = tmp_path / "run"
    asyncio.run(run_live_measurement(
        scenarios_path=scenarios_path,
        export_dir=run_dir,
        conditions=[CONDITION_C1],
        mode="deterministic",
        base_url="",
        model="",
        api_key="",
        temperature=0,
        max_iterations=4,
        estimator_interval=1,
        expulsion_threshold=5,
        limit=1,
    ))

    analysis = tmp_path / "analysis"
    sweep(run_dir, analysis, [1, 5, 10], [CONDITION_C1])

    assert (analysis / "sq2_roc_frontier.csv").exists()
    assert (analysis / "sq2_latency_fp_frontier.csv").exists()
    assert (analysis / "sq2_operating_points.csv").exists()
    assert "mean_fallout_broadcasts" in (analysis / "sq2_threshold_sweep.csv").read_text(encoding="utf-8")


def test_discover_c1_logs_excludes_failed_trial_logs(tmp_path: Path) -> None:
    scenarios = generate_scenarios(seeds_per_cell=1)[:2]
    write_scenarios(tmp_path / "sq2_scenarios.jsonl", scenarios)
    condition_dir = tmp_path / "trials" / CONDITION_C1
    for scenario in scenarios:
        trial_dir = condition_dir / scenario.scenario_id
        trial_dir.mkdir(parents=True)
        (trial_dir / "accountability.log").write_text("{}\n", encoding="utf-8")
    (tmp_path / "sq2_trials.csv").write_text(
        "scenario_id,condition,error\n"
        f"{scenarios[0].scenario_id},{CONDITION_C1},\n"
        f"{scenarios[1].scenario_id},{CONDITION_C1},TimeoutError: timed out\n",
        encoding="utf-8",
    )

    found = discover_c1_logs(tmp_path)

    assert [scenario.scenario_id for scenario, _ in found] == [scenarios[0].scenario_id]
