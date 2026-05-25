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
    assert seen["cmd"][seen["cmd"].index("--agent") + 1] == scenario_boot.DEFAULT_OPENCLAW_AGENT_ID
    assert "--json" in seen["cmd"]
    assert seen["cmd"][seen["cmd"].index("--timeout") + 1] == str(
        scenario_boot.DEFAULT_OPENCLAW_SMOKE_TIMEOUT_S
    )
    assert "capture_output" in seen["kwargs"]
    assert seen["kwargs"]["timeout"] == scenario_boot.DEFAULT_OPENCLAW_SMOKE_TIMEOUT_S + 30


def test_openclaw_inner_timeout_tracks_watchdog_interval(tmp_path: Path) -> None:
    scenario, _agent = _scenario_and_agent(tmp_path)
    assert scenario_boot._openclaw_inner_timeout_s(scenario) == 30

    longer = Scenario(
        name=scenario.name,
        description=scenario.description,
        watchdog=WatchdogPolicy(
            interval_s=240,
            max_iterations_per_turn=1,
            max_total_turns=5,
            max_wall_clock_s=300,
        ),
        agents=scenario.agents,
        log_dir=scenario.log_dir,
        manifest_path=scenario.manifest_path,
    )
    assert scenario_boot._openclaw_inner_timeout_s(longer) == 220


def test_openclaw_provider_timeout_covers_smoke_and_watchdog(monkeypatch, tmp_path: Path) -> None:
    scenario, _agent = _scenario_and_agent(tmp_path)
    monkeypatch.setattr(scenario_boot, "OPENCLAW_SMOKE_TIMEOUT_S", 210)
    assert scenario_boot._openclaw_provider_timeout_s(scenario) == 210

    longer = Scenario(
        name=scenario.name,
        description=scenario.description,
        watchdog=WatchdogPolicy(
            interval_s=300,
            max_iterations_per_turn=1,
            max_total_turns=5,
            max_wall_clock_s=300,
        ),
        agents=scenario.agents,
        log_dir=scenario.log_dir,
        manifest_path=scenario.manifest_path,
    )
    assert scenario_boot._openclaw_provider_timeout_s(longer) == 280


def test_openclaw_mcp_smoke_timeout_can_be_overridden(monkeypatch, tmp_path: Path) -> None:
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
        timeout_s=333,
    )

    assert failure is None
    assert seen["cmd"][seen["cmd"].index("--timeout") + 1] == "333"
    assert seen["kwargs"]["timeout"] == 363


def test_openclaw_mcp_smoke_resets_stale_sessions(monkeypatch, tmp_path: Path) -> None:
    scenario, agent = _scenario_and_agent(tmp_path)
    sessions = (
        scenario_boot._state_dir(scenario.name, agent.name)
        / ".openclaw"
        / "agents"
        / scenario_boot.DEFAULT_OPENCLAW_AGENT_ID
        / "sessions"
    )
    stale_file = sessions / "old.json"
    stale_dir_file = sessions / "old-session" / "turn.json"
    stale_dir_file.parent.mkdir(parents=True)
    stale_file.write_text("old", encoding="utf-8")
    stale_dir_file.write_text("old", encoding="utf-8")

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:  # noqa: ARG001
        assert not stale_file.exists()
        assert not stale_dir_file.exists()
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


def test_openclaw_mcp_smoke_timeout_reports_partial_streams(monkeypatch, tmp_path: Path) -> None:
    scenario, agent = _scenario_and_agent(tmp_path)
    monkeypatch.setenv("OPENCLAW_SMOKE_ATTEMPTS", "1")

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:  # noqa: ARG001
        raise subprocess.TimeoutExpired(
            cmd,
            timeout=240,
            output='{"payloads":[]}',
            stderr="provider retrying after 429",
        )

    monkeypatch.setattr(scenario_boot.subprocess, "run", fake_run)
    monkeypatch.setattr(scenario_boot.time, "monotonic", iter([10.0, 250.0]).__next__)

    failure = scenario_boot._openclaw_mcp_smoke_check(
        scenario,
        agent,
        expected_wallet_address="bcrt1qsmoke",
    )

    assert failure is not None
    assert "timed out after 240.0s" in failure
    assert "partial_stdout" in failure
    assert "partial_stderr='provider retrying after 429'" in failure


def test_openclaw_mcp_smoke_retries_rate_limit_then_succeeds(monkeypatch, tmp_path: Path) -> None:
    scenario, agent = _scenario_and_agent(tmp_path)
    calls = 0
    sleeps: list[int] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:  # noqa: ARG001
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"payloads":[{"text":"Request timed out before a response was generated."}]}',
                stderr="rawError=429 Provider returned error: rate limit reached",
            )
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout='{"payloads":[{"text":"bcrt1qsmoke"}]}',
            stderr="",
        )

    monkeypatch.setattr(scenario_boot.subprocess, "run", fake_run)
    monkeypatch.setattr(scenario_boot.time, "sleep", sleeps.append)

    failure = scenario_boot._openclaw_mcp_smoke_check(
        scenario,
        agent,
        expected_wallet_address="bcrt1qsmoke",
    )

    assert failure is None
    assert calls == 2
    assert sleeps == [scenario_boot.OPENCLAW_SMOKE_RETRY_BACKOFF_S]


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


def test_openclaw_mcp_smoke_missing_evidence_includes_preview(monkeypatch, tmp_path: Path) -> None:
    scenario, agent = _scenario_and_agent(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:  # noqa: ARG001
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout='{"payloads":[{"text":"I cannot access tools here."}]}',
            stderr="model warning",
        )

    monkeypatch.setattr(scenario_boot.subprocess, "run", fake_run)

    failure = scenario_boot._openclaw_mcp_smoke_check(
        scenario,
        agent,
        expected_wallet_address="bcrt1qsmoke",
    )
    assert failure is not None
    assert "assistant='I cannot access tools here.'" in failure
    assert "stderr='model warning'" in failure


def test_regtest_wallet_identity_requires_bcrt1(tmp_path: Path) -> None:
    _scenario, agent = _scenario_and_agent(tmp_path)
    regtest_agent = AgentSpec(
        name=agent.name,
        ipv8_port=agent.ipv8_port,
        mcp_port=agent.mcp_port,
        publish_overlays=agent.publish_overlays,
        mission_file=agent.mission_file,
        stop_predicate=agent.stop_predicate,
        btc_network="regtest",
    )

    assert scenario_boot._validate_agent_wallet_identity(regtest_agent, "bcrt1qok") is None
    failure = scenario_boot._validate_agent_wallet_identity(regtest_agent, "dclaw123")
    assert failure is not None
    assert "not bcrt1" in failure
