from __future__ import annotations

from pathlib import Path

import pytest

from security.containment_layer.evaluation.conditions import DEFAULT_CONDITIONS, get_condition, resolve_conditions
from security.containment_layer.evaluation.official_probe_suite import official_probe_battery, probe_spec_hash, write_probe_spec
from security.containment_layer.evaluation.official_runner import (
    APPARMOR_PROFILE_SOURCE,
    ASSET_CATEGORIES,
    ProbeRecord,
    _main_table,
    _probe_succeeded,
    _summarize,
    build_docker_command,
    run_official_sq3,
)
from security.containment_layer.infrastructure.protected_resources import create_protected_fixture, destroy_fixture


def test_factorial_conditions_cover_complete_three_by_two_design() -> None:
    conditions = resolve_conditions(None)
    assert tuple(condition.id for condition in conditions) == DEFAULT_CONDITIONS
    assert len(conditions) == 6
    cells = {(condition.factor_runtime, condition.architecture) for condition in conditions}
    assert cells == {
        ("runc", "off"),
        ("runc-hardened", "off"),
        ("gvisor", "off"),
        ("runc", "on"),
        ("runc-hardened", "on"),
        ("gvisor", "on"),
    }
    assert get_condition("C0_uncontained").host_pid_namespace is True
    assert get_condition("A1_arch_only_runc").host_pid_namespace is True
    assert get_condition("B1_runc_hardened").host_pid_namespace is False


def test_official_probe_battery_contains_boundary_family_and_legitimate_actions(tmp_path: Path) -> None:
    probes = official_probe_battery()
    attacks = [probe for probe in probes if probe.kind == "probe"]
    legitimate = [probe for probe in probes if probe.kind == "legitimate"]

    assert len(attacks) == 24
    assert len(legitimate) == 4
    assert {probe.category for probe in attacks} == set(ASSET_CATEGORIES)
    assert {probe.id for probe in attacks if probe.id.startswith("E")} >= {"E5", "E6", "E7", "E8", "E9", "E10", "E11"}
    assert {probe.id for probe in legitimate} == {"L1", "L2", "L3", "L4"}

    spec_path = tmp_path / "sq3_probe_battery.jsonl"
    assert write_probe_spec(spec_path) == probe_spec_hash()


def test_runtime_and_architecture_are_independent_in_docker_command(tmp_path: Path) -> None:
    fixture = create_protected_fixture("commands", tmp_path)
    try:
        gvisor_naive = build_docker_command(
            get_condition("B2_gvisor_naive"),
            fixture,
            image="python:3.12-slim",
            network_name="sq3",
            container_script="/workspace/probe.py",
            env=[],
            require_apparmor=False,
        )
        arch_only = build_docker_command(
            get_condition("A1_arch_only_runc"),
            fixture,
            image="python:3.12-slim",
            network_name="sq3",
            container_script="/workspace/tmp/probe.py",
            env=[],
            require_apparmor=False,
        )

        assert "--runtime=runsc" in gvisor_naive
        assert "--cap-drop=ALL" in gvisor_naive
        assert f"{fixture.root.resolve()}:/workspace:rw" in gvisor_naive
        assert f"{fixture.agent_workspace.joinpath('input').resolve()}:/workspace/input:rw" in gvisor_naive

        assert "--runtime=runsc" not in arch_only
        assert "--cap-drop=ALL" not in arch_only
        assert f"{fixture.agent_workspace.resolve()}:/workspace:rw" in arch_only
        assert str(fixture.host_protected.resolve()) not in " ".join(arch_only)
    finally:
        destroy_fixture(fixture)


def test_official_preflight_aborts_when_requested_runsc_is_missing(monkeypatch) -> None:
    from security.containment_layer.evaluation.official_runner import official_preflight

    monkeypatch.setattr("security.containment_layer.evaluation.official_runner.platform.system", lambda: "Linux")
    monkeypatch.setattr("security.containment_layer.evaluation.official_runner.os.geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        "security.containment_layer.evaluation.official_runner.shutil.which",
        lambda name: "/usr/bin/docker" if name == "docker" else None,
    )
    monkeypatch.setattr("security.containment_layer.evaluation.official_runner._apparmor_profile_loaded", lambda: True)
    monkeypatch.setattr(
        "security.containment_layer.evaluation.official_runner.detect_firewall_backend",
        lambda: type("Backend", (), {"name": "native_nftables"})(),
    )

    with pytest.raises(RuntimeError, match="runsc"):
        official_preflight([get_condition("C1_vukzero_gvisor")], image="python:3.12-slim")


def test_apparmor_profile_allows_python_runtime_libraries() -> None:
    profile = APPARMOR_PROFILE_SOURCE.read_text(encoding="utf-8")
    assert "/usr/local/lib/** mr," in profile
    assert "deny /proc/sys/** w," in profile
    assert "deny /sys/** w," in profile


def test_network_probe_scoring_uses_sink_evidence() -> None:
    for probe_id in ["D1", "D2", "D3"]:
        probe = next(item for item in official_probe_battery() if item.id == probe_id)
        assert _probe_succeeded(
            probe=probe,
            stdout=probe.success_marker,
            stderr="",
            canary_observed=False,
            protected_changed=False,
            unauthorized_network_hit=True,
            new_allowed=[],
        )
        assert not _probe_succeeded(
            probe=probe,
            stdout=probe.success_marker,
            stderr="",
            canary_observed=False,
            protected_changed=False,
            unauthorized_network_hit=False,
            new_allowed=[],
        )


def test_probe_subset_rejects_unknown_ids_before_preflight(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown hostile probe ids"):
        run_official_sq3(
            out_dir=tmp_path,
            condition_ids=["C0_uncontained"],
            probe_ids=["NOT_A_PROBE"],
            repetitions=1,
        )


def test_summary_reports_each_condition_factor_and_false_positive_rate() -> None:
    conditions = resolve_conditions(["C0_uncontained", "C1_vukzero_gvisor"])
    records = [
        _record("A1", "A_identity_key", conditions[0], "succeeded", 10.0),
        _record("A1", "A_identity_key", conditions[1], "contained", 20.0),
        _record("E5", "E_host_kernel_reach", conditions[0], "succeeded", 11.0),
        _record("E5", "E_host_kernel_reach", conditions[1], "contained", 21.0),
    ]
    for condition in conditions:
        for legitimate_id in ["L1", "L2", "L3", "L4"]:
            records.append(_record(legitimate_id, "L_legitimate", condition, "succeeded", 5.0, kind="legitimate"))

    summary = _summarize(records, {"probe_battery_sha256": "abc"}, conditions)
    assert summary["by_condition"]["C0_uncontained"]["fallout_radius"] == 2
    assert summary["by_condition"]["C1_vukzero_gvisor"]["containment_rate"] == 1.0
    assert summary["by_condition"]["C1_vukzero_gvisor"]["false_positive_rate"] == 0.0
    assert summary["by_condition"]["C1_vukzero_gvisor"]["boundary_probe_denied_rate"] == 1.0
    assert "\\toprule" in _main_table(summary)


def _record(
    probe_id: str,
    category: str,
    condition,
    outcome: str,
    latency: float,
    *,
    kind: str = "probe",
) -> ProbeRecord:
    return ProbeRecord(
        id=probe_id,
        category=category,
        condition=condition.id,
        factor_runtime=condition.factor_runtime,
        factor_architecture=condition.architecture,
        hardening=condition.hardening,
        runtime=condition.runtime_name,
        repetition=1,
        outcome=outcome,
        evidence={},
        latency_ms=latency,
        kind=kind,
    )
