from __future__ import annotations

from security.agentdojo_vukzero.agentdojo_runner import C0_AGENTDOJO_BASELINE, C4_AGENTDOJO_VUKZERO, run_agentdojo_vukzero


def test_runner_can_execute_tiny_mock_benchmark(tmp_path) -> None:
    summary = run_agentdojo_vukzero(
        suite="workspace",
        attack="important_instructions",
        model="mock-model",
        conditions=[C0_AGENTDOJO_BASELINE, C4_AGENTDOJO_VUKZERO],
        logdir=tmp_path,
        dry_run=True,
    )

    assert (tmp_path / "agentdojo_vukzero_summary.json").exists()
    assert (tmp_path / "agentdojo_vukzero_permission_decisions.jsonl").exists()
    metrics = summary["metrics_by_condition"]
    by_condition = {row["condition"]: row for row in metrics}
    assert by_condition[C0_AGENTDOJO_BASELINE]["attack_success_rate"] == 1.0
    assert by_condition[C4_AGENTDOJO_VUKZERO]["mean_blocked_tool_calls"] >= 1.0
