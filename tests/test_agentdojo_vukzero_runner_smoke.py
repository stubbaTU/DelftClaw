from __future__ import annotations

import pytest

from security.preventative_layer.agentdojo_runner import (
    C0_AGENTDOJO_BASELINE,
    C1_AGENTDOJO_VUKZERO,
    _OpenRouterChatLLM,
    _configure_agentdojo_path,
    _verify_c1_secagent_disabled,
    run_agentdojo_vukzero,
)
from security.preventative_layer.export_results import suite_results_to_trial_rows


def test_runner_can_execute_tiny_mock_benchmark(tmp_path) -> None:
    summary = run_agentdojo_vukzero(
        suite="workspace",
        attack="important_instructions",
        model="mock-model",
        conditions=[C0_AGENTDOJO_BASELINE, C1_AGENTDOJO_VUKZERO],
        logdir=tmp_path,
        dry_run=True,
    )

    assert (tmp_path / "agentdojo_vukzero_summary.json").exists()
    assert (tmp_path / "agentdojo_vukzero_permission_decisions.jsonl").exists()
    metrics = summary["metrics_by_condition"]
    by_condition = {row["condition"]: row for row in metrics}
    assert by_condition[C0_AGENTDOJO_BASELINE]["attack_success_rate"] == 1.0
    assert by_condition[C1_AGENTDOJO_VUKZERO]["mean_blocked_tool_calls"] >= 1.0


def test_suite_results_to_trial_rows_accepts_agentdojo_typed_dict() -> None:
    rows = suite_results_to_trial_rows(
        condition=C0_AGENTDOJO_BASELINE,
        suite="workspace",
        attack="important_instructions",
        model="mock",
        suite_results={
            "utility_results": {("user_task_0", "injection_task_0"): True},
            "security_results": {("user_task_0", "injection_task_0"): True},
            "injection_tasks_utility_results": {},
        },
    )

    assert rows == [{
        "condition": C0_AGENTDOJO_BASELINE,
        "suite": "workspace",
        "attack": "important_instructions",
        "model": "mock",
        "user_task_id": "user_task_0",
        "injection_task_id": "injection_task_0",
        "utility_success": True,
        "attack_success": True,
        "error": "",
        "num_tool_calls": 0,
        "num_allowed_tool_calls": 0,
        "num_blocked_tool_calls": 0,
        "blocked_reasons": "",
        "blocked_reason_codes": "",
        "blocked_denial_classes": "",
        "final_output_blocked": False,
    }]


def test_suite_results_to_trial_rows_marks_failed_injection_as_not_attack_success() -> None:
    rows = suite_results_to_trial_rows(
        condition=C1_AGENTDOJO_VUKZERO,
        suite="workspace",
        attack="important_instructions",
        model="mock",
        suite_results={
            "utility_results": {("user_task_0", "injection_task_0"): True},
            "security_results": {("user_task_0", "injection_task_0"): False},
            "injection_tasks_utility_results": {},
        },
    )

    assert rows[0]["attack_success"] is False


def test_openrouter_llm_reports_empty_provider_response() -> None:
    class FakeCompletions:
        def create(self, **kwargs):  # noqa: ANN001
            return type("Completion", (), {"choices": None})()

    class FakeClient:
        chat = type("Chat", (), {"completions": FakeCompletions()})()

    class FakeRuntime:
        functions = {}

    llm = _OpenRouterChatLLM(FakeClient(), "provider/model")

    with pytest.raises(RuntimeError, match="no completion choices"):
        llm.query("", FakeRuntime(), messages=())


def test_agentdojo_path_accepts_src_layout(tmp_path, monkeypatch) -> None:
    package = tmp_path / "src" / "agentdojo"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")

    monkeypatch.setattr("sys.path", list(__import__("sys").path))
    assert _configure_agentdojo_path(tmp_path) == package.resolve()


def test_c1_requires_secagent_to_be_disabled(monkeypatch) -> None:
    monkeypatch.delenv("SECAGENT_DISABLE", raising=False)
    with pytest.raises(RuntimeError, match="SECAGENT_DISABLE=True"):
        _verify_c1_secagent_disabled([C1_AGENTDOJO_VUKZERO])

    monkeypatch.setenv("SECAGENT_DISABLE", "True")
    _verify_c1_secagent_disabled([C1_AGENTDOJO_VUKZERO])
