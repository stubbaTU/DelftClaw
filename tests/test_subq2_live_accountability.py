from __future__ import annotations

import asyncio
import json
from pathlib import Path

from security.accountability_layer.generate_live_scenarios import FAMILIES, INTENSITIES, generate_scenarios
from security.accountability_layer.event_gateway import normalize_reputation_tool_call
from security.accountability_layer.live_orchestrator import run_live_measurement
from security.accountability_layer.live_agent_tools import event_tool_for_type, tool_args_for_event
from security.accountability_layer.live_scenario_schema import (
    CONDITION_C0,
    CONDITION_C1,
    HONEST_AGENTS,
    sanitized_event_for_agent,
    write_scenarios,
)


def test_generate_live_scenarios_produces_frozen_matrix() -> None:
    scenarios = generate_scenarios()

    assert len(scenarios) == 60
    assert {scenario.family for scenario in scenarios} == set(FAMILIES)
    assert {scenario.intensity for scenario in scenarios} == set(INTENSITIES)
    assert all(scenario.primary_attacker == "M0" for scenario in scenarios)
    assert all(scenario.honest_agents == HONEST_AGENTS for scenario in scenarios)
    assert all(scenario.events for scenario in scenarios)
    assert all(event.instruction for scenario in scenarios for event in scenario.events)
    assert all(
        scenario.first_malicious_event_index
        == next(event.index for event in scenario.events if event.ground_truth == "malicious")
        for scenario in scenarios
    )


def test_generate_live_scenarios_can_scale_beyond_paper_default() -> None:
    scenarios = generate_scenarios(seeds_per_cell=7)

    assert len(scenarios) == 4 * 3 * 7
    assert "seed07" in {scenario.scenario_id.rsplit("_", 1)[-1] for scenario in scenarios}


def test_live_orchestrator_deterministic_smoke_exports_required_files(tmp_path: Path) -> None:
    scenarios_path = tmp_path / "sq2_live_reputation_trap_scenarios.jsonl"
    write_scenarios(scenarios_path, generate_scenarios())
    out_dir = tmp_path / "results"

    report = asyncio.run(run_live_measurement(
        scenarios_path=scenarios_path,
        export_dir=out_dir,
        conditions=[CONDITION_C0, CONDITION_C1],
        mode="deterministic",
        base_url="",
        model="",
        api_key="",
        temperature=0.0,
        max_iterations=4,
        estimator_interval=1,
        expulsion_threshold=5,
        limit=2,
        start_openclaw_runtime=False,
    ))

    assert report["summary"]["trial_count"] == 4
    for filename in [
        "sq2_run_metadata.json",
        "sq2_summary.json",
        "sq2_scenarios.jsonl",
        "sq2_trials.csv",
        "sq2_trials.jsonl",
        "sq2_event_log.jsonl",
        "sq2_reputation_timeseries.csv",
        "sq2_expulsions.csv",
        "sq2_lag_by_condition.csv",
        "sq2_lag_by_family.csv",
        "sq2_fallout_by_condition.csv",
        "sq2_fallout_by_family.csv",
        "sq2_detection_reasons.csv",
        "sq2_false_positives.csv",
        "sq2_log_integrity.csv",
        "run.log",
    ]:
        assert (out_dir / filename).exists(), filename

    trial_rows = [
        json.loads(line)
        for line in (out_dir / "sq2_trials.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(trial_rows) == 4
    assert all(row["error"] is None for row in trial_rows)

    c0_lags = [row["reputation_lag_events"] for row in trial_rows if row["condition"] == CONDITION_C0]
    c1_lags = [row["reputation_lag_events"] for row in trial_rows if row["condition"] == CONDITION_C1]
    assert max(c1_lags) < max(c0_lags)


def test_c1_signed_logs_verify_and_do_not_expose_ground_truth(tmp_path: Path) -> None:
    scenarios_path = tmp_path / "sq2_live_reputation_trap_scenarios.jsonl"
    write_scenarios(scenarios_path, generate_scenarios())
    out_dir = tmp_path / "results"

    asyncio.run(run_live_measurement(
        scenarios_path=scenarios_path,
        export_dir=out_dir,
        conditions=[CONDITION_C1],
        mode="deterministic",
        base_url="",
        model="",
        api_key="",
        temperature=0.0,
        max_iterations=4,
        estimator_interval=1,
        expulsion_threshold=5,
        limit=1,
        start_openclaw_runtime=False,
    ))

    integrity_text = (out_dir / "sq2_log_integrity.csv").read_text(encoding="utf-8")
    assert "True" in integrity_text

    signed_log = next((out_dir / "trials" / CONDITION_C1).glob("*/accountability.log"))
    content = signed_log.read_text(encoding="utf-8")
    assert "ground_truth" not in content
    assert "signature" in content
    assert "entry_hash" in content


def test_sanitized_scenario_step_hides_evaluator_fields() -> None:
    event = generate_scenarios()[0].events[0]
    visible = sanitized_event_for_agent(event)

    assert "ground_truth" not in visible
    assert "first_malicious_event_index" not in visible
    assert visible["instruction"]


def test_event_gateway_normalizes_and_rejects_wrong_tool() -> None:
    scenario = generate_scenarios()[0]
    event = scenario.events[0]

    ok = normalize_reputation_tool_call(
        scenario=scenario,
        condition=CONDITION_C1,
        event=event,
        tool_name=event_tool_for_type(event.event_type),
        tool_args=tool_args_for_event(event),
    )
    bad = normalize_reputation_tool_call(
        scenario=scenario,
        condition=CONDITION_C1,
        event=event,
        tool_name="broadcast_donation",
        tool_args={},
    )

    assert ok.ok is True
    assert ok.canonical_event["source"] == "live_openclaw_tool_call"
    assert "ground_truth" not in json.dumps(ok.canonical_event)
    assert bad.ok is False
    assert "tool mismatch" in bad.reason
