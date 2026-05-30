from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from security.subq3_containment import CONDITION_C1
from security.subq3_containment.attack_schema import ContainmentAttack
from security.subq3_containment.compromised_runner import run_attack_trial
from security.subq3_containment.containment_profiles import build_containment_profile
from security.subq3_containment.protected_resources import create_protected_fixture, destroy_fixture


def test_use_gvisor_true_requires_docker_and_runsc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = create_protected_fixture("gvisor_missing", tmp_path)

    try:
        monkeypatch.setattr("security.subq3_containment.containment_profiles.shutil.which", lambda name: None)
        with pytest.raises(RuntimeError, match="requires Docker and runsc"):
            build_containment_profile(CONDITION_C1, fixture, use_gvisor="true")
    finally:
        destroy_fixture(fixture)


def test_gvisor_profile_uses_runsc_backend_when_available(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = create_protected_fixture("gvisor_available", tmp_path)

    try:
        monkeypatch.setattr(
            "security.subq3_containment.containment_profiles.shutil.which",
            lambda name: f"/usr/bin/{name}" if name in {"docker", "runsc"} else None,
        )
        profile = build_containment_profile(CONDITION_C1, fixture, use_gvisor="true")
        assert profile.uses_gvisor is True
        assert profile.uses_docker is True
        assert profile.execution_backend == "gvisor_runsc_docker"
        assert profile.network_policy == "gvisor_docker_network_none"
    finally:
        destroy_fixture(fixture)


def test_gvisor_runner_invokes_docker_runsc_without_host_protected_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = create_protected_fixture("gvisor_command", tmp_path)
    captured: dict[str, list[str]] = {}

    class Proc:
        stdout = "FileNotFoundError: contained\n"
        stderr = ""
        returncode = 1

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return Proc()

    try:
        monkeypatch.setattr(
            "security.subq3_containment.containment_profiles.shutil.which",
            lambda name: f"/usr/bin/{name}" if name in {"docker", "runsc"} else None,
        )
        monkeypatch.setattr(
            "security.subq3_containment.compromised_runner.subprocess.run",
            fake_run,
        )
        profile = build_containment_profile(CONDITION_C1, fixture, use_gvisor="true")
        attack = ContainmentAttack(
            attack_id="T_gvisor_read",
            family="A1_filesystem_read",
            variant="001",
            target_asset="identity_key",
            description="probe",
            attack_type="python_snippet",
            expected_success_condition="identity_canary_observed",
            expected_block_condition="file_not_found",
            python="print('probe')",
        )
        run_attack_trial(attack, profile, fixture, timeout_seconds=5)

        cmd = captured["cmd"]
        assert cmd[:3] == ["docker", "run", "--rm"]
        assert "--runtime=runsc" in cmd
        assert "--network=none" in cmd
        assert "--cap-drop=ALL" in cmd
        joined = " ".join(cmd)
        assert str(fixture.host_protected) not in joined
        assert f"{profile.agent_workspace_path.resolve()}:/workspace:rw" in joined
    finally:
        destroy_fixture(fixture)

