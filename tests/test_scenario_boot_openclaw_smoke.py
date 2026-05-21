from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from deploy import scenario_boot
from deploy.scenario import AgentSpec, Scenario, WatchdogPolicy


def _scenario_and_agent(tmp_path: Path) -> tuple[Scenario, AgentSpec]:
    agent = AgentSpec(
        name="alice",
        ipv8_port=8200,
        mcp_port=18865,
        publish_overlays=(),
        mission_file=tmp_path / "mission.md",
        stop_predicate="never",
    )
    scenario = Scenario(
        name="smoke",
        description="smoke",
        watchdog=WatchdogPolicy(
            interval_s=30,
            max_iterations_per_turn=1,
            max_total_turns=5,
            max_wall_clock_s=300,
        ),
        agents={"alice": agent},
        log_dir=tmp_path,
        manifest_path=tmp_path / "scenario.yaml",
    )
    return scenario, agent


def test_openclaw_mcp_smoke_success(monkeypatch, tmp_path: Path) -> None:
    scenario, agent = _scenario_and_agent(tmp_path)
    seen: dict[str, Any] = {}

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"] = cmd
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout='{"payloads":[{"text":"bcrt1qsmoke"}]}',
            stderr="",
        )

    monkeypatch.setattr(scenario_boot.subprocess, "run", fake_run)

    failure = scenario_boot._openclaw_mcp_smoke_check(
        scenario,
        agent,
        expected_wallet_address="bcrt1qsmoke",
    )
    assert failure is None
    assert seen["cmd"][:4] == ["sudo", "-u", scenario_boot.SERVICE_USER, "env"]
    assert "--agent" in seen["cmd"]
    assert "smoke-alice" in seen["cmd"]
    assert "--json" in seen["cmd"]
    assert "capture_output" in seen["kwargs"]


def test_openclaw_mcp_smoke_fails_on_literal_error(monkeypatch, tmp_path: Path) -> None:
    scenario, agent = _scenario_and_agent(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:  # noqa: ARG001
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout='{"payloads":[{"text":"ERROR"}]}',
            stderr="",
        )

    monkeypatch.setattr(scenario_boot.subprocess, "run", fake_run)

    failure = scenario_boot._openclaw_mcp_smoke_check(
        scenario,
        agent,
        expected_wallet_address="bcrt1qsmoke",
    )
    assert failure == "openclaw_semantic_error:literal_ERROR"


def test_openclaw_mcp_smoke_fails_on_nonzero_subprocess(monkeypatch, tmp_path: Path) -> None:
    scenario, agent = _scenario_and_agent(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:  # noqa: ARG001
        return subprocess.CompletedProcess(
            cmd,
            2,
            stdout="",
            stderr="bad model",
        )

    monkeypatch.setattr(scenario_boot.subprocess, "run", fake_run)

    failure = scenario_boot._openclaw_mcp_smoke_check(
        scenario,
        agent,
        expected_wallet_address="bcrt1qsmoke",
    )
    assert failure is not None
    assert "subprocess failed rc=2" in failure


def test_openclaw_mcp_smoke_requires_wallet_evidence(monkeypatch, tmp_path: Path) -> None:
    scenario, agent = _scenario_and_agent(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:  # noqa: ARG001
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout='{"payloads":[{"text":"not-the-address"}]}',
            stderr="",
        )

    monkeypatch.setattr(scenario_boot.subprocess, "run", fake_run)

    failure = scenario_boot._openclaw_mcp_smoke_check(
        scenario,
        agent,
        expected_wallet_address="bcrt1qsmoke",
    )
    assert failure is not None
    assert "missing wallet_address evidence" in failure
