from __future__ import annotations

import csv
import json
import os
import subprocess
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
from experiments.run_openclaw_llm_adversarial import (
    _run_trial,
    _summary_rows,
    assert_no_secrets,
    main as openclaw_llm_main,
    qualify_openrouter_model,
    redact_text,
    sha256_bytes,
)


def _config() -> dict:
    config = resolve_config("results/config/smoke.json", smoke=True)
    config["openclaw_llm_challenge_timeout_s"] = 0.5
    config["openclaw_llm_join_timeout_s"] = 2.0
    return config


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
