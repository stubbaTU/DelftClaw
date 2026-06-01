from __future__ import annotations

from pathlib import Path

from security.containment_layer.official_probe_suite import official_probe_battery, probe_spec_hash, write_probe_spec
from security.containment_layer.official_runner import (
    ASSET_CATEGORIES,
    CONDITION_C0,
    CONDITION_C1,
    ProbeRecord,
    _agent_egress_filter,
    _main_table,
    _probe_succeeded,
    _summarize,
)


def test_official_probe_battery_has_expected_probe_and_legitimate_counts(tmp_path: Path) -> None:
    probes = official_probe_battery()
    attack_probes = [probe for probe in probes if probe.kind == "probe"]
    legitimate = [probe for probe in probes if probe.kind == "legitimate"]

    assert len(attack_probes) == 17
    assert len(legitimate) == 4
    assert {probe.category for probe in attack_probes} == set(ASSET_CATEGORIES)
    assert {probe.id for probe in legitimate} == {"L1", "L2", "L3", "L4"}
    d3 = next(probe for probe in attack_probes if probe.id == "D3")
    assert "UNAUTHORIZED_TCP_PORT" in d3.code
    assert "bind(" not in d3.code

    spec_path = tmp_path / "sq3_probe_battery.jsonl"
    digest = write_probe_spec(spec_path)
    assert spec_path.exists()
    assert digest == probe_spec_hash()


def test_official_summary_reports_containment_fallout_and_false_positive_rate() -> None:
    records = [
        ProbeRecord("A1", "A_identity_key", CONDITION_C0, "succeeded", {}, 10.0),
        ProbeRecord("A2", "A_identity_key", CONDITION_C0, "contained", {}, 12.0),
        ProbeRecord("A1", "A_identity_key", CONDITION_C1, "contained", {}, 20.0),
        ProbeRecord("A2", "A_identity_key", CONDITION_C1, "contained", {}, 22.0),
        ProbeRecord("L1", "L_legitimate", CONDITION_C1, "succeeded", {}, 30.0, kind="legitimate"),
        ProbeRecord("L2", "L_legitimate", CONDITION_C1, "succeeded", {}, 31.0, kind="legitimate"),
        ProbeRecord("L3", "L_legitimate", CONDITION_C1, "succeeded", {}, 32.0, kind="legitimate"),
        ProbeRecord("L4", "L_legitimate", CONDITION_C1, "succeeded", {}, 33.0, kind="legitimate"),
    ]

    summary = _summarize(records, {"probe_battery_sha256": "abc"})

    assert summary["by_condition"][CONDITION_C0]["fallout_radius"] == 1
    assert summary["by_condition"][CONDITION_C1]["fallout_radius"] == 0
    assert summary["by_condition"][CONDITION_C1]["containment_rate"] == 1.0
    assert summary["legitimate_actions_c1"]["false_positive_rate"] == 0.0
    assert "\\toprule" in _main_table(summary)


def test_d3_uses_egress_sink_evidence_like_d1() -> None:
    d1 = next(probe for probe in official_probe_battery() if probe.id == "D1")
    d3 = next(probe for probe in official_probe_battery() if probe.id == "D3")

    for probe in [d1, d3]:
        assert _probe_succeeded(
            probe=probe,
            stdout="exfil_sent=True\n",
            stderr="",
            canary_observed=False,
            protected_changed=False,
            log_valid=True,
            unauthorized_network_hit=True,
            new_allowed=[],
        )
        assert not _probe_succeeded(
            probe=probe,
            stdout="",
            stderr="Connection refused",
            canary_observed=False,
            protected_changed=False,
            log_valid=True,
            unauthorized_network_hit=False,
            new_allowed=[],
        )


def test_agent_egress_filter_deletes_exact_inserted_rules(monkeypatch, tmp_path: Path) -> None:
    commands: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
        commands.append(list(cmd))

        class Result:
            stdout = ""
            stderr = ""
            returncode = 0

        return Result()

    monkeypatch.setattr("security.containment_layer.official_runner.subprocess.run", fake_run)
    monkeypatch.setattr("security.containment_layer.official_runner.shutil.which", lambda name: None)

    with _agent_egress_filter("172.31.77.11", "172.31.77.1", 12345, tmp_path):
        pass

    delete_commands = [cmd for cmd in commands if cmd[:2] == ["iptables", "-D"]]
    assert len(delete_commands) == 3
    assert all("1" not in cmd[3:] and "2" not in cmd[3:] for cmd in delete_commands)
    assert ["iptables", "-D", "INPUT", "-s", "172.31.77.11", "-d", "172.31.77.1", "-p", "tcp", "--dport", "12345", "-j", "ACCEPT"] in delete_commands
    assert ["iptables", "-D", "INPUT", "-s", "172.31.77.11", "-d", "172.31.77.1", "-j", "REJECT"] in delete_commands
    assert ["iptables", "-D", "DOCKER-USER", "-s", "172.31.77.11", "-j", "REJECT"] in delete_commands
