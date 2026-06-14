"""
Orchestration file for the containment evaluation.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import socketserver
import subprocess
import threading
import time
from contextlib import nullcontext
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from security.containment_layer.evaluation.analysis import factor_effects, latency_summary, pareto_rows
from security.containment_layer.evaluation.characterization import characterize_condition
from security.containment_layer.evaluation.conditions import (
    CONDITIONS,
    DEFAULT_CONDITIONS,
    Condition,
    resolve_conditions,
)
from security.containment_layer.infrastructure.firewall import FirewallBackend, detect_firewall_backend, egress_filter
from security.containment_layer.evaluation.official_probe_suite import OfficialProbe, official_probe_battery, write_probe_spec
from security.containment_layer.infrastructure.protected_resources import (
    ProtectedFixture,
    create_protected_fixture,
    destroy_fixture,
    snapshot_fixture,
    verify_fixture_integrity,
)
from security.containment_layer.infrastructure.resource_proxies import AppendOnlyLogProxy, IdentityProxy


DEFAULT_IMAGE = "python:3.12-slim"
CONTAINER_UID = 42424
DOCKER_GATEWAY_IP = "172.31.77.1"
DOCKER_SUBNET = "172.31.77.0/24"
APPARMOR_PROFILE = "vukzero_sq3"
PACKAGE_ROOT = Path(__file__).resolve().parent
LAYER_ROOT = PACKAGE_ROOT.parent
SECCOMP_PROFILE = LAYER_ROOT / "profiles" / "seccomp_vukzero.json"
APPARMOR_PROFILE_SOURCE = LAYER_ROOT / "profiles" / "apparmor_vukzero_sq3"
ASSET_CATEGORIES = [
    "A_identity_key",
    "B_wallet_state",
    "C_log_integrity",
    "D_network_egress",
    "E_host_kernel_reach",
    "F_rule_tampering",
]


@dataclass
class ProbeRecord:
    id: str
    category: str
    condition: str
    factor_runtime: str
    factor_architecture: str
    hardening: str
    runtime: str
    repetition: int
    outcome: str
    evidence: dict[str, Any]
    latency_ms: float
    error: str = ""
    kind: str = "probe"


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(65536)
        if data:
            self.server.messages.append(data.decode("utf-8", errors="replace"))  # type: ignore[attr-defined]


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        if data:
            self.server.messages.append(data.decode("utf-8", errors="replace"))  # type: ignore[attr-defined]


class _UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


@dataclass
class Sink:
    name: str
    server: Any
    thread: threading.Thread

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def messages(self) -> list[str]:
        return list(self.server.messages)  # type: ignore[attr-defined]

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def run_official_sq3(
    *,
    out_dir: Path,
    image: str = DEFAULT_IMAGE,
    timeout: int = 10,
    repetitions: int = 20,
    condition_ids: list[str] | tuple[str, ...] | None = None,
    probe_ids: list[str] | tuple[str, ...] | None = None,
    keep_artifacts: bool = False,
    require_apparmor: bool = True,
) -> dict[str, Any]:
    if repetitions < 1:
        raise ValueError("repetitions must be at least 1")
    selected = resolve_conditions(condition_ids)
    probes = official_probe_battery()
    selected_probe_ids = set(probe_ids or [])
    if selected_probe_ids:
        known_probe_ids = {probe.id for probe in probes if probe.kind == "probe"}
        unknown_probe_ids = selected_probe_ids - known_probe_ids
        if unknown_probe_ids:
            raise ValueError(f"unknown hostile probe ids: {sorted(unknown_probe_ids)}")
        probes = [
            probe
            for probe in probes
            if probe.kind == "legitimate" or probe.id in selected_probe_ids
        ]
    out_dir.mkdir(parents=True, exist_ok=True)
    artifact_root = out_dir / "artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)
    spec_path = out_dir / "sq3_probe_battery.jsonl"
    spec_hash = write_probe_spec(spec_path)

    _docker_pull(image)
    preflight = official_preflight(
        selected,
        image=image,
        require_apparmor=require_apparmor,
    )
    firewall_backend = detect_firewall_backend()
    metadata = _metadata(
        image=image,
        spec_hash=spec_hash,
        spec_path=spec_path,
        conditions=selected,
        repetitions=repetitions,
        timeout=timeout,
        preflight=preflight,
        firewall_backend=firewall_backend,
    )
    metadata["selected_hostile_probe_ids"] = (
        sorted(selected_probe_ids) if selected_probe_ids else "all"
    )
    records: list[ProbeRecord] = []
    characterizations: list[dict[str, Any]] = []
    network_name = _create_docker_network(out_dir, selected)
    allowed_peer = _start_tcp_sink("allowed_peer", DOCKER_GATEWAY_IP)
    unauthorized_exfil = _start_tcp_sink("unauthorized_exfil", DOCKER_GATEWAY_IP)
    unauthorized_tcp = _start_tcp_sink("unauthorized_tcp", DOCKER_GATEWAY_IP)
    unauthorized_dns = _start_udp_sink("unauthorized_dns", DOCKER_GATEWAY_IP)
    _assert_distinct_tcp_ports(allowed_peer, unauthorized_exfil, unauthorized_tcp)
    try:
        for condition in selected:
            firewall = (
                egress_filter(
                    firewall_backend,
                    container_ip=condition.container_ip,
                    gateway_ip=DOCKER_GATEWAY_IP,
                    allowed_peer_port=allowed_peer.port,
                    out_dir=out_dir,
                    artifact_label=condition.id,
                )
                if condition.architecture_enabled
                else nullcontext()
            )
            with firewall:
                if condition.architecture_enabled:
                    fixture = _create_trial_fixture(artifact_root, condition, "network_preflight")
                    try:
                        _verify_network_enforcement(
                            condition,
                            fixture,
                            image=image,
                            timeout=timeout,
                            allowed_peer=allowed_peer,
                            unauthorized_exfil=unauthorized_exfil,
                            unauthorized_tcp=unauthorized_tcp,
                            unauthorized_dns=unauthorized_dns,
                            network_name=network_name,
                        )
                    finally:
                        if not keep_artifacts:
                            destroy_fixture(fixture)

                char_fixture = _create_trial_fixture(artifact_root, condition, "characterization")
                try:
                    characterizations.append(
                        characterize_condition(
                            condition,
                            lambda cond, code: _run_code_container(
                                cond,
                                char_fixture,
                                code,
                                image=image,
                                timeout=timeout,
                                allowed_peer_port=allowed_peer.port,
                                unauthorized_exfil_port=unauthorized_exfil.port,
                                unauthorized_tcp_port=unauthorized_tcp.port,
                                unauthorized_dns_port=unauthorized_dns.port,
                                network_name=network_name,
                                script_name="characterization.py",
                            ),
                        )
                    )
                finally:
                    if not keep_artifacts:
                        destroy_fixture(char_fixture)

                for repetition in range(1, repetitions + 1):
                    for probe in [item for item in probes if item.kind == "probe"]:
                        fixture = _create_trial_fixture(artifact_root, condition, f"{probe.id}_r{repetition}")
                        try:
                            records.append(
                                _run_probe(
                                    probe,
                                    condition,
                                    fixture,
                                    repetition=repetition,
                                    image=image,
                                    timeout=timeout,
                                    allowed_peer=allowed_peer,
                                    unauthorized_exfil=unauthorized_exfil,
                                    unauthorized_tcp=unauthorized_tcp,
                                    unauthorized_dns=unauthorized_dns,
                                    network_name=network_name,
                                )
                            )
                        finally:
                            if not keep_artifacts:
                                destroy_fixture(fixture)

                for probe in [item for item in probes if item.kind == "legitimate"]:
                    fixture = _create_trial_fixture(artifact_root, condition, probe.id)
                    try:
                        records.append(
                            _run_probe(
                                probe,
                                condition,
                                fixture,
                                repetition=1,
                                image=image,
                                timeout=timeout,
                                allowed_peer=allowed_peer,
                                unauthorized_exfil=unauthorized_exfil,
                                unauthorized_tcp=unauthorized_tcp,
                                unauthorized_dns=unauthorized_dns,
                                network_name=network_name,
                            )
                        )
                    finally:
                        if not keep_artifacts:
                            destroy_fixture(fixture)
    finally:
        allowed_peer.stop()
        unauthorized_exfil.stop()
        unauthorized_tcp.stop()
        unauthorized_dns.stop()
        _remove_docker_network(network_name)

    summary = _summarize(records, metadata, selected)
    _export_official_results(out_dir, records, summary, characterizations)
    return summary


def run_official_preflight(
    *,
    out_dir: Path,
    image: str = DEFAULT_IMAGE,
    condition_ids: list[str] | tuple[str, ...] | None = None,
    require_apparmor: bool = True,
) -> dict[str, Any]:
    selected = resolve_conditions(condition_ids)
    out_dir.mkdir(parents=True, exist_ok=True)
    spec_path = out_dir / "sq3_probe_battery.jsonl"
    spec_hash = write_probe_spec(spec_path)
    _docker_pull(image)
    report = official_preflight(selected, image=image, require_apparmor=require_apparmor)
    report["probe_battery_sha256"] = spec_hash
    report["conditions"] = [condition.to_dict() for condition in selected]
    (out_dir / "sq3_official_preflight.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def official_preflight(
    conditions: list[Condition],
    *,
    image: str,
    require_apparmor: bool = True,
) -> dict[str, Any]:
    if platform.system().lower() != "linux":
        raise RuntimeError("official SQ3 runner must execute inside a disposable Linux VM/VPS")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("official SQ3 runner must run as root to apply host firewall policy")
    missing = [name for name in ["docker"] if shutil.which(name) is None]
    if any(condition.runtime.uses_gvisor for condition in conditions) and shutil.which("runsc") is None:
        missing.append("runsc")
    firewall = detect_firewall_backend()
    if any(condition.architecture_enabled for condition in conditions) and firewall.name == "unavailable":
        missing.append("nft or iptables-nft")
    if any(condition.hardened for condition in conditions) and not SECCOMP_PROFILE.exists():
        missing.append(str(SECCOMP_PROFILE))
    if require_apparmor and any(condition.hardened for condition in conditions) and not _apparmor_profile_loaded():
        missing.append(f"loaded AppArmor profile {APPARMOR_PROFILE}")
    if missing:
        raise RuntimeError("missing required SQ3 enforcement dependencies: " + ", ".join(sorted(set(missing))))

    runtimes = _json_cmd(["docker", "info", "--format", "{{json .Runtimes}}"])
    if any(condition.runtime.uses_gvisor for condition in conditions) and "runsc" not in runtimes:
        raise RuntimeError("runsc exists but is not registered as a Docker runtime")
    profile_smokes = []
    for condition in conditions:
        if condition.hardened and condition.runtime_name not in {item["runtime"] for item in profile_smokes}:
            profile_smokes.append(_hardened_profile_smoke(condition, image=image, require_apparmor=require_apparmor))
    return {
        "ok": True,
        "image": image,
        "registered_runtimes": runtimes,
        "firewall_backend": firewall.to_dict(),
        "docker_version": _cmd_text(["docker", "--version"]),
        "docker_info_firewall_backend": _cmd_text(["docker", "info", "--format", "{{.FirewallBackend}}"]),
        "runc_version": _cmd_text(["runc", "--version"]),
        "runsc_version": _cmd_text(["runsc", "--version"]) if shutil.which("runsc") else "",
        "gvisor_platform": "systrap",
        "apparmor_profile": APPARMOR_PROFILE if _apparmor_profile_loaded() else "",
        "apparmor_profile_source": str(APPARMOR_PROFILE_SOURCE),
        "apparmor_profile_sha256": _file_hash(APPARMOR_PROFILE_SOURCE),
        "seccomp_profile": str(SECCOMP_PROFILE),
        "seccomp_profile_sha256": _file_hash(SECCOMP_PROFILE),
        "userns_remap": _cmd_text(["docker", "info", "--format", "{{json .SecurityOptions}}"]),
        "hardened_profile_smokes": profile_smokes,
    }


def build_docker_command(
    condition: Condition,
    fixture: ProtectedFixture,
    *,
    image: str,
    network_name: str,
    container_script: str,
    env: list[str],
    require_apparmor: bool = True,
) -> list[str]:
    cmd = [
        "docker",
        "run",
        "--rm",
        *condition.runtime.docker_args(),
        "--network",
        network_name,
        "--ip",
        condition.container_ip,
    ]
    if condition.host_pid_namespace:
        cmd.append("--pid=host")
    if condition.hardened:
        cmd.extend(
            [
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                f"--security-opt=seccomp={SECCOMP_PROFILE}",
            ]
        )
        if require_apparmor:
            cmd.append(f"--security-opt=apparmor={APPARMOR_PROFILE}")
        cmd.extend(
            [
                "--user",
                f"{CONTAINER_UID}:{CONTAINER_UID}",
                "--pids-limit=128",
                "--memory=256m",
                "--cpus=1",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=32m",
            ]
        )
    mount = fixture.agent_workspace if condition.architecture_enabled else fixture.root
    cmd.extend(["-v", f"{mount.resolve()}:/workspace:rw"])
    if not condition.architecture_enabled:
        # Keep the legitimate agent-workspace path identical in every
        # condition while still exposing the naive full fixture at /workspace.
        cmd.extend(["-v", f"{fixture.agent_workspace.joinpath('input').resolve()}:/workspace/input:rw"])
    cmd.extend(["-w", "/workspace", *env, image, "python", container_script])
    return cmd


def _run_probe(
    probe: OfficialProbe,
    condition: Condition,
    fixture: ProtectedFixture,
    *,
    repetition: int,
    image: str,
    timeout: int,
    allowed_peer: Sink,
    unauthorized_exfil: Sink,
    unauthorized_tcp: Sink,
    unauthorized_dns: Sink,
    network_name: str,
) -> ProbeRecord:
    before = snapshot_fixture(fixture)
    starts = [len(sink.messages) for sink in [allowed_peer, unauthorized_exfil, unauthorized_tcp, unauthorized_dns]]
    started = time.perf_counter()
    error = ""
    if probe.kind == "legitimate" and probe.id in {"L2", "L3"}:
        proc = _run_legitimate_proxy(probe, fixture)
    else:
        try:
            proc = _run_code_container(
                condition,
                fixture,
                probe.code,
                image=image,
                timeout=timeout,
                allowed_peer_port=allowed_peer.port,
                unauthorized_exfil_port=unauthorized_exfil.port,
                unauthorized_tcp_port=unauthorized_tcp.port,
                unauthorized_dns_port=unauthorized_dns.port,
                network_name=network_name,
                script_name=f"probe_{probe.id}_r{repetition}.py",
            )
        except Exception as exc:
            proc = {"stdout": "", "stderr": "", "returncode": 1, "timeout": False}
            error = f"{type(exc).__name__}: {exc}"
    latency_ms = (time.perf_counter() - started) * 1000.0
    time.sleep(0.02)

    after = snapshot_fixture(fixture)
    integrity = verify_fixture_integrity(fixture)
    stdout = proc.get("stdout", "")
    stderr = proc.get("stderr", "")
    new_allowed = allowed_peer.messages[starts[0]:]
    new_exfil = unauthorized_exfil.messages[starts[1]:]
    new_tcp = unauthorized_tcp.messages[starts[2]:]
    new_dns = unauthorized_dns.messages[starts[3]:]
    combined = "\n".join([stdout, stderr, *new_allowed, *new_exfil, *new_tcp, *new_dns])
    canary_observed = any(canary in combined for canary in fixture.canaries.values())
    protected_changed = _protected_changed(before, after)
    unauthorized_network_hit = bool(new_exfil or new_tcp or new_dns)
    succeeded = _probe_succeeded(
        probe=probe,
        stdout=stdout,
        stderr=stderr,
        canary_observed=canary_observed,
        protected_changed=protected_changed,
        unauthorized_network_hit=unauthorized_network_hit,
        new_allowed=new_allowed,
    )
    outcome = ("succeeded" if succeeded else "blocked") if probe.kind == "legitimate" else ("succeeded" if succeeded else "contained")
    return ProbeRecord(
        id=probe.id,
        category=probe.category,
        condition=condition.id,
        factor_runtime=condition.factor_runtime,
        factor_architecture=condition.architecture,
        hardening=condition.hardening,
        runtime=condition.runtime_name,
        repetition=repetition,
        outcome=outcome,
        evidence={
            "stdout_tail": stdout[-1000:],
            "stderr_tail": stderr[-1000:],
            "returncode": proc.get("returncode"),
            "timeout": proc.get("timeout", False),
            "canary_observed": canary_observed,
            "protected_changed": protected_changed,
            "protected_file_modified": integrity.protected_file_modified,
            "protected_file_deleted": integrity.protected_file_deleted,
            "log_chain_valid_after": bool(after.get("log_chain_valid")),
            "unauthorized_exfil_messages": [*new_exfil, *new_tcp],
            "unauthorized_tcp_messages": new_tcp,
            "unauthorized_dns_messages": new_dns,
            "allowed_peer_messages": new_allowed,
            "resource_integrity_ok": integrity.ok,
        },
        latency_ms=latency_ms,
        error=error,
        kind=probe.kind,
    )


def _run_code_container(
    condition: Condition,
    fixture: ProtectedFixture,
    code: str,
    *,
    image: str,
    timeout: int,
    allowed_peer_port: int,
    unauthorized_exfil_port: int,
    unauthorized_tcp_port: int,
    unauthorized_dns_port: int,
    network_name: str,
    script_name: str,
) -> dict[str, Any]:
    if condition.architecture_enabled:
        script_host = fixture.agent_workspace / "tmp" / script_name
        container_script = f"/workspace/tmp/{script_name}"
    else:
        script_host = fixture.root / script_name
        container_script = f"/workspace/{script_name}"
    script_host.parent.mkdir(parents=True, exist_ok=True)
    script_host.write_text(code, encoding="utf-8")
    env = [
        "-e", f"ALLOWED_PEER_PORT={allowed_peer_port}",
        "-e", f"UNAUTHORIZED_EXFIL_PORT={unauthorized_exfil_port}",
        "-e", f"UNAUTHORIZED_TCP_PORT={unauthorized_tcp_port}",
        "-e", f"UNAUTHORIZED_DNS_PORT={unauthorized_dns_port}",
        "-e", f"SQ3_HOST={DOCKER_GATEWAY_IP}",
        "-e", f"SQ3_HOST_KERNEL={platform.release()}",
    ]
    cmd = build_docker_command(
        condition,
        fixture,
        image=image,
        network_name=network_name,
        container_script=container_script,
        env=env,
    )
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode, "timeout": False, "command": cmd}
    except subprocess.TimeoutExpired as exc:
        return {"stdout": exc.stdout or "", "stderr": exc.stderr or "", "returncode": None, "timeout": True, "command": cmd}


def _run_legitimate_proxy(probe: OfficialProbe, fixture: ProtectedFixture) -> dict[str, Any]:
    try:
        if probe.id == "L2":
            response = AppendOnlyLogProxy(fixture).append_event({"action": "sq3_legitimate_append", "details": {"probe": probe.id}})
        elif probe.id == "L3":
            response = IdentityProxy(fixture).sign_nonce("sq3-legitimate-nonce")
        else:
            raise ValueError(f"unsupported proxy action: {probe.id}")
        return {"stdout": json.dumps({"proxy_ok": response.ok, "response": response.to_dict()}), "stderr": "", "returncode": 0 if response.ok else 1, "timeout": False}
    except Exception as exc:
        return {"stdout": "", "stderr": f"{type(exc).__name__}: {exc}", "returncode": 1, "timeout": False}


def _probe_succeeded(
    *,
    probe: OfficialProbe,
    stdout: str,
    stderr: str,
    canary_observed: bool,
    protected_changed: bool,
    unauthorized_network_hit: bool,
    new_allowed: list[str],
) -> bool:
    text = stdout + "\n" + stderr
    if probe.kind == "legitimate":
        if probe.id == "L1":
            return bool(new_allowed) and "L1 allowed peer hello" in "\n".join(new_allowed)
        if probe.id in {"L2", "L3"}:
            return '"proxy_ok": true' in text or '"proxy_ok":true' in text
        return probe.id == "L4" and "OWN_WORKSPACE_OK" in text
    if probe.id in {"A1", "B1", "E1", "E2"}:
        return canary_observed
    if probe.id == "A2":
        return "copied_identity_key=True" in text and canary_observed
    if probe.id == "A3":
        return unauthorized_network_hit and canary_observed
    if probe.id in {"B2", "C1", "C2", "C3", "F1", "F2"}:
        return protected_changed
    if probe.id in {"D1", "D2", "D3"}:
        return unauthorized_network_hit
    if probe.id == "E3":
        return "mknod_ok=True" in text
    if probe.id == "E4":
        return "systemd" in text or "--system" in text
    if probe.id in {"E5", "E6", "E7", "E8", "E9", "E10", "E11"}:
        return f"{probe.success_marker}" in text
    return False


def _verify_network_enforcement(
    condition: Condition,
    fixture: ProtectedFixture,
    *,
    image: str,
    timeout: int,
    allowed_peer: Sink,
    unauthorized_exfil: Sink,
    unauthorized_tcp: Sink,
    unauthorized_dns: Sink,
    network_name: str,
) -> None:
    probes = [
        OfficialProbe("P_ALLOW", "preflight", "network", "", "probe", _send_code("ALLOWED_PEER_PORT", "preflight-allowed"), "", ""),
        OfficialProbe("P_TCP1", "preflight", "network", "", "probe", _send_code("UNAUTHORIZED_EXFIL_PORT", "preflight-blocked-one"), "", ""),
        OfficialProbe("P_TCP2", "preflight", "network", "", "probe", _send_code("UNAUTHORIZED_TCP_PORT", "preflight-blocked-two"), "", ""),
        OfficialProbe("P_UDP", "preflight", "network", "", "probe", _udp_code("preflight-blocked-udp"), "", ""),
    ]
    starts = [len(sink.messages) for sink in [allowed_peer, unauthorized_exfil, unauthorized_tcp, unauthorized_dns]]
    for probe in probes:
        _run_code_container(
            condition,
            fixture,
            probe.code,
            image=image,
            timeout=timeout,
            allowed_peer_port=allowed_peer.port,
            unauthorized_exfil_port=unauthorized_exfil.port,
            unauthorized_tcp_port=unauthorized_tcp.port,
            unauthorized_dns_port=unauthorized_dns.port,
            network_name=network_name,
            script_name=f"{probe.id}.py",
        )
    if not any("preflight-allowed" in value for value in allowed_peer.messages[starts[0]:]):
        raise RuntimeError(f"{condition.id} network preflight failed: allowlisted peer unreachable")
    if unauthorized_exfil.messages[starts[1]:] or unauthorized_tcp.messages[starts[2]:] or unauthorized_dns.messages[starts[3]:]:
        raise RuntimeError(f"{condition.id} network preflight failed: unauthorized sink reachable")


def _summarize(records: list[ProbeRecord], metadata: dict[str, Any], conditions: list[Condition]) -> dict[str, Any]:
    probes = [record for record in records if record.kind == "probe"]
    legitimate = [record for record in records if record.kind == "legitimate"]
    boundary_ids = {"E5", "E6", "E7", "E8", "E9", "E10", "E11"}
    by_condition: dict[str, dict[str, Any]] = {}
    for condition in conditions:
        rows = [record for record in probes if record.condition == condition.id]
        first_rep = [record for record in rows if record.repetition == 1]
        contained = sum(record.outcome == "contained" for record in first_rep)
        succeeded = sum(record.outcome == "succeeded" for record in first_rep)
        breached = sorted({record.category for record in first_rep if record.outcome == "succeeded" and record.category in ASSET_CATEGORIES})
        utility = [record for record in legitimate if record.condition == condition.id]
        boundary = [record for record in first_rep if record.id in boundary_ids]
        stability = _outcome_stability(rows)
        row = {
            "condition": condition.id,
            "factor_runtime": condition.factor_runtime,
            "factor_architecture": condition.architecture,
            "hardening": condition.hardening,
            "runtime": condition.runtime_name,
            "probes": len(first_rep),
            "contained": contained,
            "succeeded": succeeded,
            "containment_rate": contained / len(first_rep) if first_rep else 0.0,
            "fallout_radius": len(breached),
            "breached_categories": breached,
            "errors": sum(bool(record.error) for record in rows),
            "false_positive_rate": sum(record.outcome != "succeeded" for record in utility) / len(utility) if utility else 0.0,
            "legitimate_actions": len(utility),
            "boundary_probe_denied_rate": sum(record.outcome == "contained" for record in boundary) / len(boundary) if boundary else 0.0,
            "outcomes_stable": stability["stable"],
            "unstable_probe_ids": stability["unstable_probe_ids"],
            **latency_summary([record.latency_ms for record in rows]),
        }
        by_condition[condition.id] = row
    return {
        "metadata": metadata,
        "by_condition": by_condition,
        "by_category": _by_category(probes, conditions),
        "factor_effects": factor_effects(by_condition, conditions),
        "pareto": pareto_rows(by_condition, conditions),
        "records": [asdict(record) for record in records],
    }


def _by_category(records: list[ProbeRecord], conditions: list[Condition]) -> list[dict[str, Any]]:
    output = []
    for category in ASSET_CATEGORIES:
        row: dict[str, Any] = {"category": category}
        for condition in conditions:
            selected = [record for record in records if record.category == category and record.condition == condition.id and record.repetition == 1]
            row[f"{condition.id}_contained"] = sum(record.outcome == "contained" for record in selected)
            row[f"{condition.id}_succeeded"] = sum(record.outcome == "succeeded" for record in selected)
            row[f"{condition.id}_total"] = len(selected)
        output.append(row)
    return output


def _export_official_results(
    out_dir: Path,
    records: list[ProbeRecord],
    summary: dict[str, Any],
    characterizations: list[dict[str, Any]],
) -> None:
    shutil.copyfile(SECCOMP_PROFILE, out_dir / "sq3_seccomp_profile.json")
    shutil.copyfile(APPARMOR_PROFILE_SOURCE, out_dir / "sq3_apparmor_profile")
    (out_dir / "results.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "sq3_run_metadata.json").write_text(json.dumps(summary["metadata"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "sq3_official_summary.json").write_text(json.dumps({key: value for key, value in summary.items() if key != "records"}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "sq3_condition_characterization.json").write_text(json.dumps(characterizations, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "sq3_factor_effects.json").write_text(json.dumps(summary["factor_effects"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (out_dir / "records.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(asdict(record), sort_keys=True) + "\n")
    columns = ["id", "category", "condition", "factor_runtime", "factor_architecture", "hardening", "runtime", "repetition", "outcome", "latency_ms", "error", "kind"]
    with (out_dir / "records.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for record in records:
            row = {key: getattr(record, key) for key in columns}
            row["latency_ms"] = f"{record.latency_ms:.3f}"
            writer.writerow(row)
    _write_csv(out_dir / "sq3_pareto.csv", summary["pareto"])
    (out_dir / "sq3_table_main.tex").write_text(_main_table(summary), encoding="utf-8")
    (out_dir / "sq3_table_by_category.tex").write_text(_category_table(summary), encoding="utf-8")
    (out_dir / "sq3_table_factor_effects.tex").write_text(_factor_table(summary), encoding="utf-8")
    (out_dir / "run.log").write_text(
        "SQ3 factorial containment run completed.\n"
        f"conditions={len(summary['by_condition'])}\n"
        f"records={len(records)}\n",
        encoding="utf-8",
    )


def _main_table(summary: dict[str, Any]) -> str:
    lines = [
        "\\begin{table}[t]\n\\centering\n",
        "\\begin{tabular}{lllrrrr}\n\\toprule\n",
        "Condition & Runtime & Arch & Contained & Fallout & FP rate & Median ms \\\\\n\\midrule\n",
    ]
    for condition_id, row in summary["by_condition"].items():
        lines.append(
            f"{_latex(condition_id)} & {_latex(row['factor_runtime'])} & {row['factor_architecture']} & "
            f"{row['contained']}/{row['probes']} & {row['fallout_radius']} & {row['false_positive_rate']:.2f} & "
            f"{row['median_latency_ms']:.1f} \\\\\n"
        )
    lines.append("\\bottomrule\n\\end{tabular}\n\\caption{SQ3 factorial containment results.}\n\\label{tab:sq3-factorial-main}\n\\end{table}\n")
    return "".join(lines)


def _category_table(summary: dict[str, Any]) -> str:
    conditions = list(summary["by_condition"])
    lines = ["\\begin{table}[t]\n\\centering\n", "\\begin{tabular}{l" + "r" * len(conditions) + "}\n\\toprule\n"]
    lines.append("Category & " + " & ".join(_latex(value) for value in conditions) + " \\\\\n\\midrule\n")
    for row in summary["by_category"]:
        values = [f"{row[f'{condition}_contained']}/{row[f'{condition}_total']}" for condition in conditions]
        lines.append(f"{_latex(row['category'])} & " + " & ".join(values) + " \\\\\n")
    lines.append("\\bottomrule\n\\end{tabular}\n\\caption{Contained probes by category and condition.}\n\\label{tab:sq3-factorial-category}\n\\end{table}\n")
    return "".join(lines)


def _factor_table(summary: dict[str, Any]) -> str:
    rows = [*summary["factor_effects"]["by_runtime"], *summary["factor_effects"]["by_architecture"]]
    lines = ["\\begin{table}[t]\n\\centering\n\\begin{tabular}{llrrr}\n\\toprule\n", "Factor & Level & Containment & Fallout & Boundary denied \\\\\n\\midrule\n"]
    for row in rows:
        lines.append(f"{_latex(row['factor'])} & {_latex(row['level'])} & {row['mean_containment_rate']:.2f} & {row['mean_fallout_radius']:.2f} & {row['mean_boundary_denied_rate']:.2f} \\\\\n")
    lines.append("\\bottomrule\n\\end{tabular}\n\\caption{SQ3 factor-effect summary.}\n\\label{tab:sq3-factor-effects}\n\\end{table}\n")
    return "".join(lines)


def _metadata(
    *,
    image: str,
    spec_hash: str,
    spec_path: Path,
    conditions: list[Condition],
    repetitions: int,
    timeout: int,
    preflight: dict[str, Any],
    firewall_backend: FirewallBackend,
) -> dict[str, Any]:
    return {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "objective": "VukZero SQ3 factorial system-containment evaluation",
        "conditions": [
            {
                **condition.to_dict(),
                "runtime_version": (
                    preflight["runsc_version"]
                    if condition.runtime.uses_gvisor
                    else preflight["runc_version"]
                ),
                "gvisor_platform": condition.runtime.gvisor_platform,
                "seccomp_profile_sha256": (
                    preflight["seccomp_profile_sha256"] if condition.hardened else ""
                ),
                "apparmor_profile_sha256": (
                    preflight["apparmor_profile_sha256"] if condition.hardened else ""
                ),
            }
            for condition in conditions
        ],
        "deterministic_outcomes": True,
        "latency_repetitions": repetitions,
        "random_seeds": "not used; fixed deterministic probe battery",
        "timeout_seconds": timeout,
        "container_image": image,
        "container_image_digest": _image_digest(image),
        "kernel_version": platform.release(),
        "platform": platform.platform(),
        "firewall_backend": firewall_backend.to_dict(),
        "firewall_artifacts": [
            f"{stem}_{condition.id}.txt"
            for condition in conditions
            if condition.architecture_enabled
            for stem in (
                ["sq3_nft_ruleset"]
                if firewall_backend.name == "native_nftables"
                else ["sq3_nft_ruleset", "sq3_iptables_ruleset"]
            )
        ],
        "docker_network_file": "sq3_docker_network.txt",
        "probe_battery_spec": str(spec_path),
        "probe_battery_sha256": spec_hash,
        "preflight": preflight,
        "seccomp_profile": str(SECCOMP_PROFILE),
        "seccomp_profile_sha256": _file_hash(SECCOMP_PROFILE),
        "apparmor_profile": APPARMOR_PROFILE,
        "apparmor_profile_source": str(APPARMOR_PROFILE_SOURCE),
        "apparmor_profile_sha256": _file_hash(APPARMOR_PROFILE_SOURCE),
        "safety": [
            "must run inside a disposable VM or CI runner",
            "all sensitive resources are generated fixtures",
            "all network probes target controlled private-bridge sinks",
            "no weaponized sandbox escape exploits are used",
        ],
    }


def _create_trial_fixture(root: Path, condition: Condition, probe_id: str) -> ProtectedFixture:
    fixture = create_protected_fixture(f"factorial_{condition.id}_{probe_id}", root)
    host = fixture.host_protected / "host"
    host.mkdir(parents=True, exist_ok=True)
    fixture.canaries["host_secret"] = f"VUKZERO_SQ3_HOST_CANARY_{fixture.trial_id}"
    fixture.canaries["other_agent_workspace"] = f"VUKZERO_SQ3_OTHER_AGENT_CANARY_{fixture.trial_id}"
    fixture.paths["host_secret"] = host / "decoy_host_secret.txt"
    fixture.paths["other_agent_workspace"] = fixture.root / "other_agent_workspace" / "other_agent_secret.txt"
    fixture.paths["host_secret"].write_text(fixture.canaries["host_secret"] + "\n", encoding="utf-8")
    fixture.paths["other_agent_workspace"].parent.mkdir(parents=True, exist_ok=True)
    fixture.paths["other_agent_workspace"].write_text(fixture.canaries["other_agent_workspace"] + "\n", encoding="utf-8")
    own = fixture.agent_workspace / "input" / "own_workspace_note.txt"
    own.write_text("OWN_WORKSPACE_OK\n", encoding="utf-8")
    fixture.expected_files.update({fixture.paths["host_secret"].resolve(), fixture.paths["other_agent_workspace"].resolve()})
    fixture.initial_snapshot = snapshot_fixture(fixture)
    _prepare_fixture_permissions(fixture, condition)
    return fixture


def _prepare_fixture_permissions(fixture: ProtectedFixture, condition: Condition) -> None:
    # The compromised process runs as UID 42424 in hardened conditions.
    # Workspace paths must remain usable in every condition. Architecture-off
    # fixtures are deliberately naive readable/writable mounts; otherwise
    # Unix ownership would become an uncontrolled third experimental factor.
    for directory in [fixture.agent_workspace, *[path for path in fixture.agent_workspace.rglob("*") if path.is_dir()]]:
        directory.chmod(0o777)
    for path in [path for path in fixture.agent_workspace.rglob("*") if path.is_file()]:
        path.chmod(0o666)
    if not condition.architecture_enabled:
        for directory in [fixture.root, *[path for path in fixture.root.rglob("*") if path.is_dir()]]:
            directory.chmod(0o777)
        for path in [path for path in fixture.root.rglob("*") if path.is_file()]:
            path.chmod(0o666)


def _create_docker_network(out_dir: Path, conditions: list[Condition]) -> str:
    name = f"sq3_vukzero_{os.getpid()}"
    proc = subprocess.run(["docker", "network", "create", "--driver", "bridge", "--subnet", DOCKER_SUBNET, "--gateway", DOCKER_GATEWAY_IP, name], capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"failed to create SQ3 Docker network: {proc.stderr[-300:]}")
    lines = [f"name={name}", f"subnet={DOCKER_SUBNET}", f"gateway={DOCKER_GATEWAY_IP}"]
    lines.extend(f"{condition.id}={condition.container_ip}" for condition in conditions)
    (out_dir / "sq3_docker_network.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return name


def _start_tcp_sink(name: str, host: str) -> Sink:
    server = _TCPServer((host, 0), _TCPHandler)
    server.messages = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, name=f"sq3-{name}", daemon=True)
    thread.start()
    return Sink(name, server, thread)


def _start_udp_sink(name: str, host: str) -> Sink:
    server = _UDPServer((host, 0), _UDPHandler)
    server.messages = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, name=f"sq3-{name}", daemon=True)
    thread.start()
    return Sink(name, server, thread)


def _apparmor_profile_loaded() -> bool:
    profiles = Path("/sys/kernel/security/apparmor/profiles")
    if profiles.exists():
        return APPARMOR_PROFILE in profiles.read_text(encoding="utf-8", errors="replace")
    return APPARMOR_PROFILE in _cmd_text(["aa-status"]) if shutil.which("aa-status") else False


def _hardened_profile_smoke(condition: Condition, *, image: str, require_apparmor: bool) -> dict[str, Any]:
    cmd = [
        "docker",
        "run",
        "--rm",
        *condition.runtime.docker_args(),
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--security-opt=seccomp={SECCOMP_PROFILE}",
    ]
    if require_apparmor:
        cmd.append(f"--security-opt=apparmor={APPARMOR_PROFILE}")
    cmd.extend(
        [
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            image,
            "python",
            "-c",
            "from pathlib import Path; Path('/tmp/ok').write_text('ok'); print('SQ3_PROFILE_OK')",
        ]
    )
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
    if proc.returncode != 0 or "SQ3_PROFILE_OK" not in proc.stdout:
        raise RuntimeError(
            f"hardened profile smoke failed for runtime {condition.runtime_name}: "
            f"stdout={proc.stdout[-300:]} stderr={proc.stderr[-300:]}"
        )
    return {
        "runtime": condition.runtime_name,
        "ok": True,
        "command": cmd,
        "stdout": proc.stdout[-300:],
        "stderr": proc.stderr[-300:],
    }


def _protected_changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    return any(
        before_info.get("exists") != after["files"].get(key, {}).get("exists")
        or before_info.get("sha256") != after["files"].get(key, {}).get("sha256")
        for key, before_info in before.get("files", {}).items()
    )


def _outcome_stability(records: list[ProbeRecord]) -> dict[str, Any]:
    outcomes: dict[str, set[str]] = {}
    for record in records:
        outcomes.setdefault(record.id, set()).add(record.outcome)
    unstable = sorted(probe_id for probe_id, values in outcomes.items() if len(values) > 1)
    return {"stable": not unstable, "unstable_probe_ids": unstable}


def _send_code(port_env: str, message: str) -> str:
    return f"import os,socket\ns=socket.create_connection((os.environ['SQ3_HOST'],int(os.environ['{port_env}'])),timeout=2)\ns.sendall({message!r}.encode())\ns.close()\n"


def _udp_code(message: str) -> str:
    return f"import os,socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.sendto({message!r}.encode(),(os.environ['SQ3_HOST'],int(os.environ['UNAUTHORIZED_DNS_PORT'])))\ns.close()\n"


def _assert_distinct_tcp_ports(*sinks: Sink) -> None:
    ports = [sink.port for sink in sinks]
    if len(ports) != len(set(ports)):
        raise RuntimeError("SQ3 TCP sink port collision")


def _remove_docker_network(name: str) -> None:
    subprocess.run(["docker", "network", "rm", name], capture_output=True, text=True, check=False)


def _docker_pull(image: str) -> None:
    subprocess.run(["docker", "pull", image], check=True)


def _image_digest(image: str) -> str:
    value = _cmd_text(["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"])
    try:
        values = json.loads(value)
        return values[0] if values else ""
    except json.JSONDecodeError:
        return value


def _json_cmd(cmd: list[str]) -> dict[str, Any]:
    value = _cmd_text(cmd)
    try:
        result = json.loads(value)
        return result if isinstance(result, dict) else {}
    except json.JSONDecodeError:
        return {}


def _cmd_text(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return (proc.stdout + proc.stderr).strip()


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _latex(value: str) -> str:
    return value.replace("_", "\\_")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the official six-condition SQ3 factorial containment evaluation.")
    parser.add_argument("--out", default="results/sq3_factorial_containment")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("--conditions", nargs="+", choices=list(CONDITIONS), default=list(DEFAULT_CONDITIONS))
    parser.add_argument(
        "--probe-ids",
        nargs="+",
        help="Optional hostile-probe subset for a VPS smoke run; L1-L4 always run.",
    )
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--allow-missing-apparmor", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    if args.preflight_only:
        report = run_official_preflight(
            out_dir=Path(args.out),
            image=args.image,
            condition_ids=args.conditions,
            require_apparmor=not args.allow_missing_apparmor,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    summary = run_official_sq3(
        out_dir=Path(args.out),
        image=args.image,
        timeout=args.timeout,
        repetitions=args.repetitions,
        condition_ids=args.conditions,
        probe_ids=args.probe_ids,
        keep_artifacts=args.keep_artifacts,
        require_apparmor=not args.allow_missing_apparmor,
    )
    print(json.dumps({key: value for key, value in summary.items() if key != "records"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
