from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
from fastmcp import Client

from deploy import openclaw_workspace
from deploy.openclaw_workspace import OpenClawWorkspaceSpec
from experiments.common.config import resolve_config
from experiments.common.validation import (
    OPENCLAW_LLM_ADVERSARIAL_SCHEMA,
    OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA,
)
from experiments.openclaw_llm_controller import (
    LineageExperimentController,
    build_experiment_mcp_server,
)
from experiments.recover_openclaw_llm_run import recover_run
from experiments.run_openclaw_llm_adversarial import (
    _await_mcp,
    _run_trial,
    _select_trials,
    _start_mcp_http_server,
    _stop_mcp_http_server,
    _free_tcp_port,
    _summary_rows,
    ProgressReporter,
    TimingCollector,
    assert_no_secrets,
    build_prompt,
    main as openclaw_llm_main,
    qualify_openrouter_model,
    redact_text,
    sha256_bytes,
)


def _selection_args(**overrides) -> argparse.Namespace:
    values = {
        "milestone": False,
        "lineage_mode": None,
        "attack_case": None,
        "trial_index": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _config() -> dict:
    config = resolve_config("results/config/smoke.json", smoke=True)
    config["openclaw_llm_challenge_timeout_s"] = 0.5
    config["openclaw_llm_join_timeout_s"] = 2.0
    return config


def test_select_trials_defaults_to_configured_matrix() -> None:
    config = _config()
    modes, cases, trial_indices = _select_trials(_selection_args(), config)
    assert modes == config["openclaw_llm_lineage_modes"]
    assert cases == config["openclaw_llm_attack_cases"]
    assert trial_indices == [0]


def test_select_trials_supports_an_exact_subset() -> None:
    config = _config()
    config["openclaw_llm_trials_per_case"] = 3
    args = _selection_args(
        lineage_mode=["optional"],
        attack_case=["cloned_agent_identity"],
        trial_index=[2],
    )
    assert _select_trials(args, config) == (
        ["optional"],
        ["cloned_agent_identity"],
        [2],
    )


def test_select_trials_rejects_out_of_range_index() -> None:
    config = _config()
    config["openclaw_llm_trials_per_case"] = 3
    with pytest.raises(ValueError, match="between 0 and 2"):
        _select_trials(_selection_args(trial_index=[3]), config)


def test_prompt_requires_sequential_tool_calls() -> None:
    prompt = build_prompt(
        trial_id="test-trial",
        mode="required",
        attack_case="valid_agent_baseline",
    )
    prepare = prompt.index("lineage_experiment_prepare_case")
    request = prompt.index("lineage_experiment_request_join")
    status = prompt.index("lineage_experiment_peer_status")
    assert prepare < request < status
    assert "never call them in parallel or batch them" in prompt
    assert "After it succeeds" in prompt
    assert "After that succeeds" in prompt


def test_recover_interrupted_run_writes_raw_and_summary(tmp_path: Path) -> None:
    run_dir = tmp_path / "20260608-120000Z-test"
    artifact_dir = (
        run_dir
        / "raw"
        / "openclaw_llm_adversarial"
        / "openclaw-llm-optional-valid_agent_baseline-trial-0000"
    )
    artifact_dir.mkdir(parents=True)
    (run_dir / "tables").mkdir()
    config = _config()
    (run_dir / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (run_dir / "environment.json").write_text(json.dumps({
        "git_commit": "abc123",
        "python_version": "3.11.0",
        "platform": "test-platform",
    }), encoding="utf-8")
    (run_dir / "preflight.json").write_text(json.dumps({
        "openclaw": {"openclaw_version": "openclaw test"},
    }), encoding="utf-8")
    protocol = {
        "selected_attack_case": "valid_agent_baseline",
        "join_attempted": True,
        "proof_supplied": True,
        "expected_accept": True,
        "join_accepted": True,
        "lineage_status": "valid",
        "rejected": False,
        "false_accept": False,
        "protocol_expectation_met": True,
        "lineage_errors": [],
    }
    metadata = {
        "provider": "openrouter",
        "model": "openrouter/owl-alpha",
        "model_ref": "openrouter/openrouter/owl-alpha",
        "openclaw_version": "openclaw test",
        "agent_id": "lineage-test",
        "temperature": 0.0,
        "model_seed": 123,
        "max_tokens": 1024,
        "timing_seconds": {"prepare": 0.1, "openclaw_model_tool_loop": 1.2},
    }
    ledger = [
        {"tool": "lineage_experiment_prepare_case", "ok": True},
        {"tool": "lineage_experiment_request_join", "ok": True},
        {"tool": "lineage_experiment_peer_status", "ok": True},
    ]
    files = {
        "prompt.txt": "test prompt",
        "openclaw_stdout.json": json.dumps({
            "payloads": [{"text": "complete"}],
            "meta": {},
        }),
        "openclaw_stderr.txt": "",
        "tool_calls.jsonl": "".join(json.dumps(row) + "\n" for row in ledger),
        "protocol_result.json": json.dumps(protocol),
        "metadata.json": json.dumps(metadata),
        "artifact_manifest.json": json.dumps({"artifacts": {}}),
    }
    for name, content in files.items():
        (artifact_dir / name).write_text(content, encoding="utf-8")

    raw_path, summary_path = recover_run(run_dir)
    with raw_path.open(encoding="utf-8", newline="") as handle:
        raw_rows = list(csv.DictReader(handle))
    with summary_path.open(encoding="utf-8", newline="") as handle:
        summary_rows = list(csv.DictReader(handle))
    assert len(raw_rows) == 1
    assert raw_rows[0]["trial_id"].endswith("trial-0000")
    assert raw_rows[0]["result"] == "measured"
    assert summary_rows[0]["trials"] == "1"
    assert summary_rows[0]["llm_task_successes"] == "1"


def _controller(
    tmp_path: Path,
    attack_case: str,
    *,
    trial_index: int = 0,
) -> LineageExperimentController:
    return LineageExperimentController(
        config=_config(),
        experiment_name="openclaw_llm_adversarial",
        mode="required",
        target_attack_case=attack_case,
        trial_index=trial_index,
        trial_id=f"test-{attack_case}-{trial_index}",
        trial_root=tmp_path / f"runtime-{trial_index}",
        ledger_path=tmp_path / f"ledger-{trial_index}.jsonl",
    )


@pytest.mark.asyncio
async def test_controller_enforces_state_machine_and_valid_baseline(tmp_path: Path) -> None:
    controller = _controller(tmp_path, "valid_agent_baseline")
    try:
        early_join = await controller.request_join()
        assert early_join["ok"] is False
        assert "case_not_prepared" in early_join["error"]

        wrong = await controller.prepare_case("tampered_parent_signature")
        assert wrong["ok"] is False
        assert "wrong_attack_case" in wrong["error"]

        prepared = await controller.prepare_case("valid_agent_baseline")
        assert prepared["ok"] is True
        duplicate = await controller.prepare_case("valid_agent_baseline")
        assert duplicate["ok"] is False
        assert "case_already_prepared" in duplicate["error"]

        joined = await controller.request_join()
        assert joined == {
            "ok": True,
            "join_attempted": True,
            "join_accepted": True,
        }
        repeated = await controller.request_join()
        assert repeated["ok"] is False
        assert "join_already_attempted" in repeated["error"]

        status = await controller.peer_status()
        assert status["ok"] is True
        assert status["lineage_status"] == "valid"
        result = controller.protocol_result()
        assert result["protocol_expectation_met"] is True
        assert result["join_accepted"] is True
        ledger_rows = [
            json.loads(line)
            for line in controller.ledger_path.read_text(encoding="utf-8").splitlines()
        ]
        assert all(row["duration_ms"] >= 0 for row in ledger_rows)
    finally:
        await controller.stop()


@pytest.mark.asyncio
async def test_controller_resolves_relative_trial_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _config()
    monkeypatch.chdir(tmp_path)
    controller = LineageExperimentController(
        config=config,
        experiment_name="openclaw_llm_adversarial",
        mode="required",
        target_attack_case="valid_agent_baseline",
        trial_index=0,
        trial_id="test-relative-root",
        trial_root=Path("results/runtime"),
        ledger_path=Path("results/tool_calls.jsonl"),
    )
    try:
        prepared = await controller.prepare_case("valid_agent_baseline")
        assert prepared["ok"] is True
        assert controller.trial_root == (tmp_path / "results" / "runtime").resolve()
        joined = await controller.request_join()
        assert joined["join_accepted"] is True
    finally:
        await controller.stop()


@pytest.mark.asyncio
async def test_controller_rejects_tampered_parent_signature(tmp_path: Path) -> None:
    controller = _controller(tmp_path, "tampered_parent_signature", trial_index=1)
    try:
        assert (await controller.prepare_case("tampered_parent_signature"))["ok"] is True
        joined = await controller.request_join()
        assert joined["ok"] is True
        assert joined["join_accepted"] is False
        status = await controller.peer_status()
        assert status["lineage_status"] == "invalid"
        result = controller.protocol_result()
        assert result["protocol_expectation_met"] is True
        assert result["false_accept"] is False
    finally:
        await controller.stop()


@pytest.mark.asyncio
async def test_experiment_mcp_exposes_exactly_three_tools(tmp_path: Path) -> None:
    controller = _controller(tmp_path, "valid_agent_baseline")
    server = build_experiment_mcp_server(controller)
    async with Client(server) as client:
        tools = await client.list_tools()
    assert {tool.name for tool in tools} == {
        "lineage_experiment_prepare_case",
        "lineage_experiment_request_join",
        "lineage_experiment_peer_status",
    }


@pytest.mark.asyncio
async def test_trial_mcp_http_server_restarts_cleanly(tmp_path: Path) -> None:
    for trial_index in range(2):
        controller = _controller(
            tmp_path,
            "tampered_parent_signature",
            trial_index=trial_index,
        )
        mcp = build_experiment_mcp_server(controller)
        port = _free_tcp_port()
        url = f"http://127.0.0.1:{port}/mcp"
        server, task = _start_mcp_http_server(
            mcp,
            host="127.0.0.1",
            port=port,
        )
        try:
            await _await_mcp(url)
            async with Client(url) as client:
                result = await client.call_tool(
                    "lineage_experiment_prepare_case",
                    {"attack_case": "tampered_parent_signature"},
                )
            assert result.is_error is False
        finally:
            await controller.stop()
            await _stop_mcp_http_server(server, task)
        assert task.done()
        assert task.exception() is None


def test_redaction_hash_and_schemas() -> None:
    secret = "sk-or-v1-super-secret-value"
    redacted = redact_text(f"Authorization: Bearer {secret}", secrets=(secret,))
    assert secret not in redacted
    assert "[REDACTED]" in redacted
    assert sha256_bytes(b"abc") == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )
    assert len(OPENCLAW_LLM_ADVERSARIAL_SCHEMA) == len(
        set(OPENCLAW_LLM_ADVERSARIAL_SCHEMA)
    )
    assert OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA[-1] == "false_accepts"


def test_artifact_secret_scan_rejects_leaks(tmp_path: Path) -> None:
    secret = "sk-or-v1-secret-for-test"
    safe = tmp_path / "safe.txt"
    safe.write_text("nothing sensitive", encoding="utf-8")
    assert_no_secrets(tmp_path, secrets=(secret,))
    safe.write_text(secret, encoding="utf-8")
    with pytest.raises(RuntimeError, match="leaked"):
        assert_no_secrets(tmp_path, secrets=(secret,))


def test_openrouter_model_qualification_checks_required_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self) -> bytes:
            return json.dumps({
                "data": [{
                    "id": "openrouter/owl-alpha",
                    "canonical_slug": "openrouter/owl-alpha",
                    "supported_parameters": ["tools", "temperature", "seed"],
                    "pricing": {"prompt": "0", "completion": "0"},
                }]
            }).encode("utf-8")

    monkeypatch.setattr(
        "experiments.run_openclaw_llm_adversarial.urllib.request.urlopen",
        lambda *args, **kwargs: Response(),
    )
    qualified = qualify_openrouter_model("openrouter/owl-alpha")
    assert qualified["qualified"] is True
    assert qualified["pricing"]["prompt"] == "0"


def test_summary_excludes_missing_join_from_protocol_denominator() -> None:
    rows = [
        {
            "lineage_mode": "required",
            "attack_case": "tampered_parent_signature",
            "llm_task_success": False,
            "join_attempted": False,
            "protocol_expectation_met": False,
            "false_accept": False,
        },
        {
            "lineage_mode": "required",
            "attack_case": "tampered_parent_signature",
            "llm_task_success": True,
            "join_attempted": True,
            "protocol_expectation_met": True,
            "false_accept": False,
        },
    ]
    summary = _summary_rows(rows)[0]
    assert summary["trials"] == 2
    assert summary["llm_task_success_rate"] == 0.5
    assert summary["join_attempts"] == 1
    assert summary["protocol_correct_rate"] == 1.0


@pytest.mark.asyncio
async def test_runner_records_no_tool_model_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "experiments.run_openclaw_llm_adversarial.provision_openclaw_workspace",
        lambda spec: None,
    )
    monkeypatch.setattr(
        "experiments.run_openclaw_llm_adversarial.invoke_openclaw_agent",
        lambda spec, prompt: subprocess.CompletedProcess(
            ["openclaw"],
            0,
            stdout='{"payloads":[{"text":"I did not call tools."}]}',
            stderr="",
        ),
    )
    run_dir = tmp_path / "run"
    (run_dir / "raw").mkdir(parents=True)
    row = await _run_trial(
        config=_config(),
        environment={
            "git_commit": "abc123",
            "python_version": "3.11",
            "platform": "test",
        },
        preflight={"openclaw": {"openclaw_version": "openclaw stub"}},
        run_dir=run_dir,
        mode="required",
        attack_case="valid_agent_baseline",
        trial_index=0,
    )
    assert set(row) == set(OPENCLAW_LLM_ADVERSARIAL_SCHEMA)
    assert row["llm_task_success"] is False
    assert row["join_attempted"] is False
    assert row["result"] == "llm_task_failure"
    assert row["ok"] is True
    assert row["tool_ledger_sha256"]
    assert row["artifact_manifest_sha256"]


@pytest.mark.asyncio
async def test_runner_reports_heartbeat_and_collects_stage_timings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "experiments.run_openclaw_llm_adversarial.provision_openclaw_workspace",
        lambda spec: None,
    )

    def slow_agent(spec, prompt):
        time.sleep(0.04)
        return subprocess.CompletedProcess(
            ["openclaw"],
            0,
            stdout='{"payloads":[{"text":"Done."}]}',
            stderr="",
        )

    monkeypatch.setattr(
        "experiments.run_openclaw_llm_adversarial.invoke_openclaw_agent",
        slow_agent,
    )
    messages: list[tuple[str, str]] = []
    progress = ProgressReporter(total_trials=1, progress_interval_s=0.01)
    progress.log = lambda stage, message, *args: messages.append(
        (stage, message % args)
    )
    timings = TimingCollector()
    run_dir = tmp_path / "run"
    (run_dir / "raw").mkdir(parents=True)

    await _run_trial(
        config=_config(),
        environment={
            "git_commit": "abc123",
            "python_version": "3.11",
            "platform": "test",
        },
        preflight={"openclaw": {"openclaw_version": "openclaw stub"}},
        run_dir=run_dir,
        mode="required",
        attack_case="valid_agent_baseline",
        trial_index=0,
        progress=progress,
        timings=timings,
    )

    assert any("event=heartbeat" in message for _, message in messages)
    assert timings.stages["trial.llm_api_wait_estimate"][0] >= 0.03
    assert "trial.workspace_provision" in timings.stages
    assert timings.trials[0]["stages"]["openclaw_model_tool_loop"] >= 0.03


def test_provisioning_uses_env_reference_and_non_reserved_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    configured: list[tuple[str, object]] = []
    commands: list[list[str]] = []

    def fake_set(path: str, value: object, **kwargs) -> None:
        configured.append((path, value))

    def fake_run(args, **kwargs):
        commands.append(list(args))
        stdout = '{"agents":[]}' if args[:3] == ["agents", "list", "--json"] else ""
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(openclaw_workspace, "set_openclaw_config", fake_set)
    monkeypatch.setattr(openclaw_workspace, "run_openclaw_cli", fake_run)
    spec = OpenClawWorkspaceSpec(
        home=tmp_path,
        agent_id="lineage-test",
        mcp_name="lineage-mcp",
        mcp_url="http://127.0.0.1:18888/mcp",
    )
    openclaw_workspace.provision_openclaw_workspace(spec)

    provider = dict(configured)["models.providers.openrouter"]
    assert provider["apiKey"] == "OPENROUTER_API_KEY"
    configured_map = dict(configured)
    assert configured_map["tools.profile"] == "coding"
    assert configured_map["tools.allow"] == ["bundle-mcp"]
    assert spec.model_ref == "openrouter/openrouter/owl-alpha"
    assert any(command[:2] == ["agents", "add"] for command in commands)
    mcp_set = next(command for command in commands if command[:2] == ["mcp", "set"])
    mcp_config = json.loads(mcp_set[3])
    assert mcp_config["toolFilter"]["include"] == list(
        openclaw_workspace.EXPERIMENT_TOOLS
    )
    assert ["mcp", "show", spec.mcp_name] in commands
    assert all("sk-or-" not in json.dumps(value) for _, value in configured)

    reserved = OpenClawWorkspaceSpec(
        home=tmp_path / "reserved",
        agent_id="main",
        mcp_name="mcp",
        mcp_url="http://127.0.0.1:1/mcp",
    )
    with pytest.raises(ValueError, match="reserved"):
        openclaw_workspace.provision_openclaw_workspace(reserved)


def test_openclaw_preflight_accepts_stub_executable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("the production runner targets Linux; .cmd lookup differs on Windows")
    executable = tmp_path / "openclaw"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--version\" ]; then echo 'openclaw 2099.1.0'; exit 0; fi\n"
        "echo '--local --agent --message --json --timeout "
        "--workspace --agent-dir --model --non-interactive'\n",
        encoding="ascii",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    result = openclaw_workspace.openclaw_preflight()
    assert result["openclaw_version"] == "openclaw 2099.1.0"
    assert result["required_flags_present"] is True


def test_openclaw_preflight_rejects_cli_without_mcp_show(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_capture(args, **kwargs):
        if args[:3] == ["mcp", "show", "--help"]:
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="unknown command")
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=(
                "openclaw 2099.1.0\n"
                "--local --agent --message --json --timeout "
                "--workspace --agent-dir --model --non-interactive"
            ),
            stderr="",
        )

    monkeypatch.setattr(openclaw_workspace, "run_openclaw_cli", fake_capture)
    monkeypatch.setattr(openclaw_workspace.shutil, "which", lambda _: "/usr/bin/openclaw")

    with pytest.raises(RuntimeError, match="mcp show"):
        openclaw_workspace.openclaw_preflight()


@pytest.mark.skipif(
    os.environ.get("RUN_OPENCLAW_VPS_ACCEPTANCE") != "1",
    reason="set RUN_OPENCLAW_VPS_ACCEPTANCE=1 on the configured Linux VPS",
)
def test_real_openclaw_openrouter_milestone_acceptance(tmp_path: Path) -> None:
    assert os.environ.get("OPENROUTER_API_KEY")
    rc = openclaw_llm_main([
        "--config",
        "results/config/smoke.json",
        "--out",
        str(tmp_path),
        "--milestone",
    ])
    assert rc == 0
    csvs = list(tmp_path.glob("*/raw/openclaw_llm_adversarial.csv"))
    assert len(csvs) == 1
    with csvs[0].open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    by_case = {row["attack_case"]: row for row in rows}
    assert by_case["valid_agent_baseline"]["join_accepted"] == "True"
    assert by_case["valid_agent_baseline"]["lineage_status"] == "valid"
    assert by_case["tampered_parent_signature"]["join_accepted"] == "False"
    assert by_case["tampered_parent_signature"]["lineage_status"] == "invalid"
