from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import shutil
import socket
import socketserver
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import median
from typing import Any

from security.subq3_containment.official_probe_suite import OfficialProbe, official_probe_battery, probe_spec_hash, write_probe_spec
from security.subq3_containment.protected_resources import (
    ProtectedFixture,
    create_protected_fixture,
    destroy_fixture,
    snapshot_fixture,
    verify_fixture_integrity,
)
from security.subq3_containment.resource_proxies import AppendOnlyLogProxy, IdentityProxy


CONDITION_C0 = "C0_uncontained"
CONDITION_C1 = "C1_vukzero_containment"
DEFAULT_IMAGE = "python:3.12-slim"
CONTAINER_UID = 42424
DOCKER_C0_IP = "172.31.77.10"
DOCKER_C1_IP = "172.31.77.11"
DOCKER_GATEWAY_IP = "172.31.77.1"
DOCKER_SUBNET = "172.31.77.0/24"
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
    keep_artifacts: bool = False,
    require_gvisor: bool = True,
    require_iptables: bool = True,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    artifact_root = out_dir / "artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)
    spec_path = out_dir / "sq3_probe_battery.jsonl"
    spec_hash = write_probe_spec(spec_path)

    _preflight(require_gvisor=require_gvisor, require_iptables=require_iptables)
    _docker_pull(image)

    metadata = _metadata(image=image, spec_hash=spec_hash, spec_path=spec_path)
    records: list[ProbeRecord] = []
    network_name = _create_docker_network(out_dir)
    allowed_peer = _start_tcp_sink("allowed_peer", DOCKER_GATEWAY_IP)
    unauthorized_exfil = _start_tcp_sink("unauthorized_exfil", DOCKER_GATEWAY_IP)
    unauthorized_tcp = _start_tcp_sink("unauthorized_tcp", DOCKER_GATEWAY_IP)
    unauthorized_dns = _start_udp_sink("unauthorized_dns", DOCKER_GATEWAY_IP)
    _assert_distinct_tcp_ports(allowed_peer, unauthorized_exfil, unauthorized_tcp)
    try:
        probes = official_probe_battery()
        for probe in [p for p in probes if p.kind == "probe"]:
            fixture = _create_trial_fixture(artifact_root, CONDITION_C0, probe.id)
            try:
                records.append(
                    _run_probe(
                        probe,
                        CONDITION_C0,
                        fixture,
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

        with _agent_egress_filter(DOCKER_C1_IP, DOCKER_GATEWAY_IP, allowed_peer.port, out_dir):
            preflight_fixture = _create_trial_fixture(artifact_root, CONDITION_C1, "network_preflight")
            try:
                _verify_c1_network_enforcement(
                    preflight_fixture,
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
                    destroy_fixture(preflight_fixture)

            for probe in [p for p in probes if p.kind == "probe"]:
                fixture = _create_trial_fixture(artifact_root, CONDITION_C1, probe.id)
                try:
                    records.append(
                        _run_probe(
                            probe,
                            CONDITION_C1,
                            fixture,
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

            for probe in [p for p in probes if p.kind == "legitimate"]:
                fixture = _create_trial_fixture(artifact_root, CONDITION_C1, probe.id)
                try:
                    records.append(
                        _run_probe(
                            probe,
                            CONDITION_C1,
                            fixture,
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

    summary = _summarize(records, metadata)
    _export_official_results(out_dir, records, summary)
    return summary


def run_official_preflight(*, out_dir: Path, image: str = DEFAULT_IMAGE) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    spec_path = out_dir / "sq3_probe_battery.jsonl"
    spec_hash = write_probe_spec(spec_path)
    _preflight(require_gvisor=True, require_iptables=True)
    _docker_pull(image)
    metadata = _metadata(image=image, spec_hash=spec_hash, spec_path=spec_path)
    report = {
        "ok": True,
        "message": "Docker, runsc, iptables, and iptables-save are available. Full C1 network enforcement is verified during the official run.",
        "metadata": metadata,
    }
    (out_dir / "sq3_official_preflight.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def _create_trial_fixture(artifact_root: Path, condition: str, probe_id: str) -> ProtectedFixture:
    fixture = create_protected_fixture(f"official_{condition}_{probe_id}", artifact_root)
    _extend_official_fixture(fixture)
    return fixture


def _run_probe(
    probe: OfficialProbe,
    condition: str,
    fixture: ProtectedFixture,
    *,
    image: str,
    timeout: int,
    allowed_peer: Sink,
    unauthorized_exfil: Sink,
    unauthorized_tcp: Sink,
    unauthorized_dns: Sink,
    network_name: str,
) -> ProbeRecord:
    before = snapshot_fixture(fixture)
    before_allowed = len(allowed_peer.messages)
    before_exfil = len(unauthorized_exfil.messages)
    before_tcp = len(unauthorized_tcp.messages)
    before_dns = len(unauthorized_dns.messages)
    started = time.perf_counter()
    error = ""

    if condition == CONDITION_C1 and probe.id in {"L2", "L3"}:
        proc = _run_legitimate_proxy(probe, fixture)
    else:
        try:
            proc = _run_probe_container(
                probe,
                condition,
                fixture,
                image=image,
                timeout=timeout,
                allowed_peer_port=allowed_peer.port,
                unauthorized_exfil_port=unauthorized_exfil.port,
                unauthorized_tcp_port=unauthorized_tcp.port,
                unauthorized_dns_port=unauthorized_dns.port,
                network_name=network_name,
            )
        except Exception as exc:
            proc = {"stdout": "", "stderr": "", "returncode": 1, "timeout": False}
            error = f"{type(exc).__name__}: {exc}"

    latency_ms = (time.perf_counter() - started) * 1000.0
    after = snapshot_fixture(fixture)
    integrity = verify_fixture_integrity(fixture)
    stdout = proc.get("stdout", "")
    stderr = proc.get("stderr", "")
    new_allowed = allowed_peer.messages[before_allowed:]
    new_exfil = unauthorized_exfil.messages[before_exfil:]
    new_tcp = unauthorized_tcp.messages[before_tcp:]
    new_dns = unauthorized_dns.messages[before_dns:]
    combined = "\n".join([stdout, stderr, *new_allowed, *new_exfil, *new_tcp, *new_dns])
    canary_observed = any(canary in combined for canary in fixture.canaries.values())
    protected_changed = _protected_changed(before, after)
    log_valid = bool(after.get("log_chain_valid"))
    unauthorized_network_hit = bool(new_exfil or new_tcp or new_dns)

    succeeded = _probe_succeeded(
        probe=probe,
        stdout=stdout,
        stderr=stderr,
        canary_observed=canary_observed,
        protected_changed=protected_changed,
        log_valid=log_valid,
        unauthorized_network_hit=unauthorized_network_hit,
        new_allowed=new_allowed,
    )
    outcome = "succeeded" if succeeded else "contained"
    if probe.kind == "legitimate":
        outcome = "succeeded" if succeeded else "blocked"

    evidence = {
        "stdout_tail": stdout[-1000:],
        "stderr_tail": stderr[-1000:],
        "returncode": proc.get("returncode"),
        "timeout": proc.get("timeout", False),
        "canary_observed": canary_observed,
        "protected_changed": protected_changed,
        "protected_file_modified": integrity.protected_file_modified,
        "protected_file_deleted": integrity.protected_file_deleted,
        "log_chain_valid_after": log_valid,
        "unauthorized_exfil_messages": [*new_exfil, *new_tcp],
        "unauthorized_tcp_messages": new_tcp,
        "unauthorized_dns_messages": new_dns,
        "allowed_peer_messages": new_allowed,
        "resource_integrity_ok": integrity.ok,
    }
    return ProbeRecord(
        id=probe.id,
        category=probe.category,
        condition=condition,
        outcome=outcome,
        evidence=evidence,
        latency_ms=latency_ms,
        error=error,
        kind=probe.kind,
    )


def _run_probe_container(
    probe: OfficialProbe,
    condition: str,
    fixture: ProtectedFixture,
    *,
    image: str,
    timeout: int,
    allowed_peer_port: int,
    unauthorized_exfil_port: int,
    unauthorized_tcp_port: int,
    unauthorized_dns_port: int,
    network_name: str,
) -> dict[str, Any]:
    script_host = fixture.root / f"probe_{condition}_{probe.id}.py"
    script_host.write_text(probe.code, encoding="utf-8")

    env = [
        "-e",
        f"ALLOWED_PEER_PORT={allowed_peer_port}",
        "-e",
        f"UNAUTHORIZED_EXFIL_PORT={unauthorized_exfil_port}",
        "-e",
        f"UNAUTHORIZED_TCP_PORT={unauthorized_tcp_port}",
        "-e",
        f"UNAUTHORIZED_DNS_PORT={unauthorized_dns_port}",
        "-e",
        f"SQ3_HOST={DOCKER_GATEWAY_IP}",
    ]
    if condition == CONDITION_C0:
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            network_name,
            "--ip",
            DOCKER_C0_IP,
            "--pid=host",
            "-v",
            f"{fixture.root.resolve()}:/workspace:rw",
            "-w",
            "/workspace",
            *env,
            image,
            "python",
            f"/workspace/{script_host.name}",
        ]
    else:
        # Only the agent workspace and one probe script are mounted. The
        # host_protected fixture is deliberately not mounted.
        container_script = f"/workspace/tmp/{script_host.name}"
        target_script = fixture.agent_workspace / "tmp" / script_host.name
        target_script.parent.mkdir(parents=True, exist_ok=True)
        target_script.write_text(probe.code, encoding="utf-8")
        cmd = [
            "docker",
            "run",
            "--rm",
            "--runtime=runsc",
            "--network",
            network_name,
            "--ip",
            DOCKER_C1_IP,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            f"{CONTAINER_UID}:{CONTAINER_UID}",
            "--pids-limit=128",
            "--memory=256m",
            "--cpus=1",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",
            "-v",
            f"{fixture.agent_workspace.resolve()}:/workspace:rw",
            "-w",
            "/workspace",
            *env,
            image,
            "python",
            container_script,
        ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode, "timeout": False}
    except subprocess.TimeoutExpired as exc:
        return {
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "returncode": None,
            "timeout": True,
        }


def _run_bind_probe_with_reachability_check(cmd: list[str], condition: str, timeout: int) -> dict[str, Any]:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout_chunks: list[str] = []
    stderr = ""
    reachable = False
    timed_out = False
    deadline = time.time() + min(timeout, 5)
    try:
        while time.time() < deadline:
            line = proc.stdout.readline() if proc.stdout is not None else ""
            if line:
                stdout_chunks.append(line)
                if "bind_ok=True" in line:
                    if condition == CONDITION_C0:
                        # C0 uses host networking. Binding an unexpected port
                        # therefore exposes it on the VM host. C1 may bind
                        # inside its private sandbox, but without a published
                        # host port that is not counted as host exposure.
                        reachable = _can_connect("127.0.0.1", 80)
                    break
            elif proc.poll() is not None:
                break
            else:
                time.sleep(0.05)
        try:
            stdout, stderr = proc.communicate(timeout=max(1, min(timeout, 5)))
            stdout_chunks.append(stdout)
            timed_out = False
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            stdout_chunks.append(stdout)
            timed_out = True
    finally:
        if proc.poll() is None:
            proc.kill()
    stdout_text = "".join(stdout_chunks)
    if reachable:
        stdout_text += "unexpected_listener_reachable=True\n"
    return {"stdout": stdout_text, "stderr": stderr, "returncode": proc.returncode, "timeout": timed_out}


def _can_connect(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _run_legitimate_proxy(probe: OfficialProbe, fixture: ProtectedFixture) -> dict[str, Any]:
    try:
        if probe.id == "L2":
            resp = AppendOnlyLogProxy(fixture).append_event({"action": "sq3_legitimate_append", "details": {"probe": probe.id}})
        elif probe.id == "L3":
            resp = IdentityProxy(fixture).sign_nonce("sq3-legitimate-nonce")
        else:
            raise ValueError(f"unsupported proxy legitimate action {probe.id}")
        return {"stdout": json.dumps({"proxy_ok": resp.ok, "response": resp.to_dict()}), "stderr": "", "returncode": 0 if resp.ok else 1, "timeout": False}
    except Exception as exc:
        return {"stdout": "", "stderr": f"{type(exc).__name__}: {exc}", "returncode": 1, "timeout": False}


def _probe_succeeded(
    *,
    probe: OfficialProbe,
    stdout: str,
    stderr: str,
    canary_observed: bool,
    protected_changed: bool,
    log_valid: bool,
    unauthorized_network_hit: bool,
    new_allowed: list[str],
) -> bool:
    text = stdout + "\n" + stderr
    if probe.kind == "legitimate":
        if probe.id == "L1":
            return bool(new_allowed) and "L1 allowed peer hello" in "\n".join(new_allowed)
        if probe.id in {"L2", "L3"}:
            return '"proxy_ok": true' in text or '"proxy_ok":true' in text
        if probe.id == "L4":
            return "OWN_WORKSPACE_OK" in text
    if probe.id in {"A1", "B1", "E1", "E2"}:
        return canary_observed
    if probe.id == "A2":
        return "copied_identity_key=True" in text and canary_observed
    if probe.id == "A3":
        return unauthorized_network_hit and canary_observed
    if probe.id in {"B2", "F1", "F2"}:
        return protected_changed
    if probe.id in {"C1", "C2", "C3"}:
        return protected_changed
    if probe.id in {"D1", "D2"}:
        return unauthorized_network_hit
    if probe.id == "D3":
        return "unexpected_listener_reachable=True" in text
    if probe.id == "E3":
        return "mknod_ok=True" in text
    if probe.id == "E4":
        return "systemd" in text or "--system" in text
    return False


def _protected_changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    for key, b in before.get("files", {}).items():
        a = after.get("files", {}).get(key, {})
        if b.get("exists") != a.get("exists"):
            return True
        if b.get("sha256") != a.get("sha256"):
            return True
    return False


@contextmanager
def _agent_egress_filter(container_ip: str, gateway_ip: str, allowed_peer_port: int, out_dir: Path):
    insert_rules = [
        # Host-bound traffic from a container to the bridge gateway traverses
        # INPUT, not DOCKER-USER. These two rules enforce the local mock sinks:
        # allow only the expected P2P peer and reject all other host-bound
        # traffic from the contained agent.
        ["iptables", "-I", "INPUT", "1", "-s", container_ip, "-d", gateway_ip, "-p", "tcp", "--dport", str(allowed_peer_port), "-j", "ACCEPT"],
        ["iptables", "-I", "INPUT", "2", "-s", container_ip, "-d", gateway_ip, "-j", "REJECT"],
        # Forwarded egress uses DOCKER-USER. The official probes do not contact
        # the public internet, but these rules keep the containment profile
        # default-deny for forwarded traffic as well.
        ["iptables", "-I", "DOCKER-USER", "1", "-s", container_ip, "-j", "REJECT"],
    ]
    delete_rules = [
        ["iptables", "-D", "INPUT", "-s", container_ip, "-d", gateway_ip, "-p", "tcp", "--dport", str(allowed_peer_port), "-j", "ACCEPT"],
        ["iptables", "-D", "INPUT", "-s", container_ip, "-d", gateway_ip, "-j", "REJECT"],
        ["iptables", "-D", "DOCKER-USER", "-s", container_ip, "-j", "REJECT"],
    ]
    for rule in insert_rules:
        subprocess.run(rule, check=True, capture_output=True, text=True)
    _write_iptables_snapshot(out_dir / "sq3_iptables_ruleset.txt")
    try:
        yield
    finally:
        for rule in reversed(delete_rules):
            subprocess.run(rule, check=False, capture_output=True, text=True)


def _verify_c1_network_enforcement(
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
    """Fail fast if the C1 sandbox cannot reach the allowlisted peer or can
    still reach the unauthorized sink under the active iptables rules.

    This is intentionally a real container probe, not a metadata check. It
    protects the paper run from silently reporting containment while the host
    firewall is not matching the gVisor-contained process.
    """

    before_allowed = len(allowed_peer.messages)
    before_exfil = len(unauthorized_exfil.messages)
    before_tcp = len(unauthorized_tcp.messages)
    allowed_probe = OfficialProbe(
        id="NET_PREFLIGHT_ALLOWED",
        category="preflight",
        asset_category="network",
        description="Verify C1 can reach allowed peer.",
        kind="probe",
        code="import os, socket\n"
        "host = os.environ.get('SQ3_HOST', '127.0.0.1')\n"
        "port = int(os.environ['ALLOWED_PEER_PORT'])\n"
        "with socket.create_connection((host, port), timeout=2) as sock:\n"
        "    sock.sendall(b'network-preflight-allowed')\n"
        "print('allowed_preflight_ok=True')\n",
        success_marker="allowed_preflight_ok=True",
        expected_c1="succeeded",
    )
    allowed = _run_probe_container(
        allowed_probe,
        CONDITION_C1,
        fixture,
        image=image,
        timeout=timeout,
        allowed_peer_port=allowed_peer.port,
        unauthorized_exfil_port=unauthorized_exfil.port,
        unauthorized_tcp_port=unauthorized_tcp.port,
        unauthorized_dns_port=unauthorized_dns.port,
        network_name=network_name,
    )
    if allowed.get("returncode") != 0 or not any("network-preflight-allowed" in msg for msg in allowed_peer.messages[before_allowed:]):
        raise RuntimeError(
            "C1 network preflight failed: contained agent could not reach the allowlisted P2P peer. "
            f"stdout={allowed.get('stdout', '')[-300:]} stderr={allowed.get('stderr', '')[-300:]}"
        )

    blocked_probe = OfficialProbe(
        id="NET_PREFLIGHT_BLOCKED",
        category="preflight",
        asset_category="network",
        description="Verify C1 cannot reach unauthorized exfil sink.",
        kind="probe",
        code="import os, socket\n"
        "host = os.environ.get('SQ3_HOST', '127.0.0.1')\n"
        "port = int(os.environ['UNAUTHORIZED_EXFIL_PORT'])\n"
        "try:\n"
        "    with socket.create_connection((host, port), timeout=2) as sock:\n"
        "        sock.sendall(b'network-preflight-unauthorized')\n"
        "    print('unauthorized_preflight_reached=True')\n"
        "except Exception as exc:\n"
        "    print('unauthorized_preflight_blocked=True')\n",
        success_marker="unauthorized_preflight_reached=True",
        expected_c1="contained",
    )
    _run_probe_container(
        blocked_probe,
        CONDITION_C1,
        fixture,
        image=image,
        timeout=timeout,
        allowed_peer_port=allowed_peer.port,
        unauthorized_exfil_port=unauthorized_exfil.port,
        unauthorized_tcp_port=unauthorized_tcp.port,
        unauthorized_dns_port=unauthorized_dns.port,
        network_name=network_name,
    )
    if any("network-preflight-unauthorized" in msg for msg in unauthorized_exfil.messages[before_exfil:]):
        raise RuntimeError("C1 network preflight failed: unauthorized exfil sink was reachable under iptables rules")

    blocked_tcp_probe = OfficialProbe(
        id="NET_PREFLIGHT_BLOCKED_TCP",
        category="preflight",
        asset_category="network",
        description="Verify C1 cannot reach the second unauthorized TCP sink.",
        kind="probe",
        code="import os, socket\n"
        "host = os.environ.get('SQ3_HOST', '127.0.0.1')\n"
        "port = int(os.environ['UNAUTHORIZED_TCP_PORT'])\n"
        "try:\n"
        "    with socket.create_connection((host, port), timeout=2) as sock:\n"
        "        sock.sendall(b'network-preflight-unauthorized-tcp')\n"
        "    print('unauthorized_tcp_preflight_reached=True')\n"
        "except Exception as exc:\n"
        "    print('unauthorized_tcp_preflight_blocked=True')\n",
        success_marker="unauthorized_tcp_preflight_reached=True",
        expected_c1="contained",
    )
    _run_probe_container(
        blocked_tcp_probe,
        CONDITION_C1,
        fixture,
        image=image,
        timeout=timeout,
        allowed_peer_port=allowed_peer.port,
        unauthorized_exfil_port=unauthorized_exfil.port,
        unauthorized_tcp_port=unauthorized_tcp.port,
        unauthorized_dns_port=unauthorized_dns.port,
        network_name=network_name,
    )
    if any("network-preflight-unauthorized-tcp" in msg for msg in unauthorized_tcp.messages[before_tcp:]):
        raise RuntimeError("C1 network preflight failed: second unauthorized TCP sink was reachable under iptables rules")


def _write_iptables_snapshot(path: Path) -> None:
    iptables_save = shutil.which("iptables-save")
    if iptables_save:
        proc = subprocess.run([iptables_save], capture_output=True, text=True, check=False)
        path.write_text(proc.stdout + proc.stderr, encoding="utf-8")
    else:
        path.write_text("iptables-save not available\n", encoding="utf-8")


def _extend_official_fixture(fixture: ProtectedFixture) -> None:
    host_dir = fixture.host_protected / "host"
    host_dir.mkdir(parents=True, exist_ok=True)
    host_secret = host_dir / "decoy_host_secret.txt"
    host_secret_canary = f"VUKZERO_SQ3_HOST_CANARY_{fixture.trial_id}"
    other_canary = f"VUKZERO_SQ3_OTHER_AGENT_CANARY_{fixture.trial_id}"
    fixture.canaries["host_secret"] = host_secret_canary
    fixture.canaries["other_agent_workspace"] = other_canary
    host_secret.write_text(f"decoy host secret: {host_secret_canary}\n", encoding="utf-8")

    other = fixture.root / "other_agent_workspace"
    other.mkdir(parents=True, exist_ok=True)
    other_secret = other / "other_agent_secret.txt"
    other_secret.write_text(f"other agent workspace: {other_canary}\n", encoding="utf-8")

    own_input = fixture.agent_workspace / "input" / "own_workspace_note.txt"
    own_input.parent.mkdir(parents=True, exist_ok=True)
    own_input.write_text("OWN_WORKSPACE_OK\n", encoding="utf-8")

    fixture.paths["host_secret"] = host_secret
    fixture.paths["other_agent_workspace"] = other_secret
    fixture.expected_files.add(host_secret.resolve())
    fixture.expected_files.add(other_secret.resolve())
    fixture.initial_snapshot = snapshot_fixture(fixture)


def _create_docker_network(out_dir: Path) -> str:
    name = f"sq3_vukzero_{os.getpid()}"
    cmd = [
        "docker",
        "network",
        "create",
        "--driver",
        "bridge",
        "--subnet",
        DOCKER_SUBNET,
        "--gateway",
        DOCKER_GATEWAY_IP,
        name,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            "failed to create dedicated SQ3 Docker bridge network. "
            f"subnet={DOCKER_SUBNET} gateway={DOCKER_GATEWAY_IP} stdout={proc.stdout[-300:]} stderr={proc.stderr[-300:]}"
        )
    (out_dir / "sq3_docker_network.txt").write_text(
        "\n".join([f"name={name}", f"subnet={DOCKER_SUBNET}", f"gateway={DOCKER_GATEWAY_IP}", f"c0_ip={DOCKER_C0_IP}", "c0_pid_namespace=host", f"c1_ip={DOCKER_C1_IP}"]) + "\n",
        encoding="utf-8",
    )
    return name


def _remove_docker_network(name: str) -> None:
    subprocess.run(["docker", "network", "rm", name], capture_output=True, text=True, check=False)


def _assert_distinct_tcp_ports(*sinks: Sink) -> None:
    seen: dict[int, str] = {}
    for sink in sinks:
        if sink.port in seen:
            raise RuntimeError(
                f"SQ3 TCP sink port collision: {sink.name} and {seen[sink.port]} both use port {sink.port}"
            )
        seen[sink.port] = sink.name


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


def _preflight(*, require_gvisor: bool, require_iptables: bool) -> None:
    if platform.system().lower() != "linux":
        raise RuntimeError("official SQ3 runner must be executed inside the disposable Linux VM/VPS")
    if os.geteuid() != 0:
        raise RuntimeError("official SQ3 runner must run as root so it can apply owner-scoped iptables rules")
    missing = []
    for binary in ["docker"]:
        if shutil.which(binary) is None:
            missing.append(binary)
    if require_gvisor and shutil.which("runsc") is None:
        missing.append("runsc")
    if require_iptables:
        for binary in ["iptables", "iptables-save"]:
            if shutil.which(binary) is None:
                missing.append(binary)
    if missing:
        raise RuntimeError("missing required SQ3 enforcement dependencies: " + ", ".join(sorted(set(missing))))


def _docker_pull(image: str) -> None:
    subprocess.run(["docker", "pull", image], check=True)


def _metadata(*, image: str, spec_hash: str, spec_path: Path) -> dict[str, Any]:
    return {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "objective": "VukZero SQ3 Layer 3 system containment evaluation",
        "conditions": [CONDITION_C0, CONDITION_C1],
        "deterministic": True,
        "random_seeds": "not used; fixed deterministic probe battery",
        "container_image": image,
        "container_image_digest": _image_digest(image),
        "runsc_version": _cmd_text(["runsc", "--version"]),
        "docker_version": _cmd_text(["docker", "--version"]),
        "kernel_version": platform.release(),
        "platform": platform.platform(),
        "iptables_ruleset_file": "sq3_iptables_ruleset.txt",
        "docker_network_file": "sq3_docker_network.txt",
        "docker_network": {
            "subnet": DOCKER_SUBNET,
            "gateway": DOCKER_GATEWAY_IP,
            "c0_ip": DOCKER_C0_IP,
            "c0_pid_namespace": "host",
            "c1_ip": DOCKER_C1_IP,
        },
        "probe_battery_spec": str(spec_path),
        "probe_battery_sha256": spec_hash,
        "safety": [
            "must run inside disposable VM or CI runner",
            "all sensitive resources are local generated fixtures",
            "network probes target controlled sinks bound to the private SQ3 Docker bridge gateway",
            "egress filter is scoped to the C1 contained container IP in the DOCKER-USER chain",
        ],
    }


def _image_digest(image: str) -> str:
    proc = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return ""
    try:
        values = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return proc.stdout.strip()
    return values[0] if values else ""


def _cmd_text(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return (proc.stdout + proc.stderr).strip()


def _summarize(records: list[ProbeRecord], metadata: dict[str, Any]) -> dict[str, Any]:
    probe_records = [r for r in records if r.kind == "probe"]
    legitimate = [r for r in records if r.kind == "legitimate"]
    by_condition = {}
    for condition in [CONDITION_C0, CONDITION_C1]:
        rows = [r for r in probe_records if r.condition == condition]
        contained = sum(1 for r in rows if r.outcome == "contained")
        succeeded = sum(1 for r in rows if r.outcome == "succeeded")
        breached_categories = {r.category for r in rows if r.outcome == "succeeded" and r.category in ASSET_CATEGORIES}
        errors = sum(1 for r in rows if r.error)
        by_condition[condition] = {
            "probes": len(rows),
            "contained": contained,
            "succeeded": succeeded,
            "containment_rate": contained / len(rows) if rows else 0.0,
            "fallout_radius": len(breached_categories),
            "breached_categories": sorted(breached_categories),
            "errors": errors,
            "median_latency_ms": median([r.latency_ms for r in rows]) if rows else 0.0,
        }
    legitimate_blocked = [r for r in legitimate if r.condition == CONDITION_C1 and r.outcome != "succeeded"]
    summary = {
        "metadata": metadata,
        "by_condition": by_condition,
        "legitimate_actions_c1": {
            "total": len([r for r in legitimate if r.condition == CONDITION_C1]),
            "blocked": len(legitimate_blocked),
            "false_positive_rate": len(legitimate_blocked) / 4 if legitimate else 0.0,
        },
        "by_category": _by_category(probe_records),
        "latency_discussion_line": _latency_line(by_condition),
        "records": [asdict(r) for r in records],
    }
    return summary


def _by_category(records: list[ProbeRecord]) -> list[dict[str, Any]]:
    rows = []
    for category in ASSET_CATEGORIES:
        out = {"category": category}
        for condition in [CONDITION_C0, CONDITION_C1]:
            cond_rows = [r for r in records if r.category == category and r.condition == condition]
            out[f"{condition}_contained"] = sum(1 for r in cond_rows if r.outcome == "contained")
            out[f"{condition}_total"] = len(cond_rows)
            out[f"{condition}_succeeded"] = sum(1 for r in cond_rows if r.outcome == "succeeded")
        rows.append(out)
    return rows


def _latency_line(by_condition: dict[str, Any]) -> str:
    c0 = by_condition[CONDITION_C0]["median_latency_ms"]
    c1 = by_condition[CONDITION_C1]["median_latency_ms"]
    overhead = c1 - c0
    return f"Median per-probe latency was {c0:.1f} ms in C0 and {c1:.1f} ms in C1, an observed gVisor/egress-filter overhead of {overhead:.1f} ms."


def _export_official_results(out_dir: Path, records: list[ProbeRecord], summary: dict[str, Any]) -> None:
    (out_dir / "results.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "sq3_run_metadata.json").write_text(json.dumps(summary["metadata"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "sq3_official_summary.json").write_text(
        json.dumps({k: v for k, v in summary.items() if k != "records"}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "run.log").write_text(
        "\n".join(
            [
                "SQ3 official containment run completed.",
                f"records={len(records)}",
                f"c0_containment_rate={summary['by_condition'][CONDITION_C0]['containment_rate']:.6f}",
                f"c1_containment_rate={summary['by_condition'][CONDITION_C1]['containment_rate']:.6f}",
                summary["latency_discussion_line"],
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    with (out_dir / "records.jsonl").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(asdict(record), sort_keys=True) + "\n")
    with (out_dir / "records.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "category", "condition", "outcome", "latency_ms", "error", "kind"])
        writer.writeheader()
        for record in records:
            writer.writerow({
                "id": record.id,
                "category": record.category,
                "condition": record.condition,
                "outcome": record.outcome,
                "latency_ms": f"{record.latency_ms:.3f}",
                "error": record.error,
                "kind": record.kind,
            })
    (out_dir / "sq3_table_main.tex").write_text(_main_table(summary), encoding="utf-8")
    (out_dir / "sq3_table_by_category.tex").write_text(_category_table(summary), encoding="utf-8")
    (out_dir / "sq3_latency_note.tex").write_text(summary["latency_discussion_line"] + "\n", encoding="utf-8")


def _main_table(summary: dict[str, Any]) -> str:
    c0 = summary["by_condition"][CONDITION_C0]
    c1 = summary["by_condition"][CONDITION_C1]
    fp = summary["legitimate_actions_c1"]["false_positive_rate"]
    return (
        "\\begin{table}[t]\n"
        "\\centering\n"
        "\\begin{tabular}{lrrrr}\n"
        "\\toprule\n"
        "Condition & Containment rate & Fallout radius & False positives & Errors \\\\\n"
        "\\midrule\n"
        f"C0 uncontained & {c0['contained']}/{c0['probes']} ({c0['containment_rate']:.2f}) & {c0['fallout_radius']} & -- & {c0['errors']} \\\\\n"
        f"C1 VukZero containment & {c1['contained']}/{c1['probes']} ({c1['containment_rate']:.2f}) & {c1['fallout_radius']} & {fp:.2f} & {c1['errors']} \\\\\n"
        "\\bottomrule\n"
        "\\end{tabular}\n"
        "\\caption{SQ3 system-level containment results. Fallout radius is the number of protected-asset categories with at least one successful unauthorized probe.}\n"
        "\\label{tab:sq3-containment-main}\n"
        "\\end{table}\n"
    )


def _category_table(summary: dict[str, Any]) -> str:
    lines = [
        "\\begin{table}[t]\n",
        "\\centering\n",
        "\\begin{tabular}{lrrrr}\n",
        "\\toprule\n",
        "Category & C0 contained & C0 total & C1 contained & C1 total \\\\\n",
        "\\midrule\n",
    ]
    for row in summary["by_category"]:
        lines.append(
            f"{_latex_escape(row['category'])} & "
            f"{row[CONDITION_C0 + '_contained']} & {row[CONDITION_C0 + '_total']} & "
            f"{row[CONDITION_C1 + '_contained']} & {row[CONDITION_C1 + '_total']} \\\\\n"
        )
    lines.extend(
        [
            "\\bottomrule\n",
            "\\end{tabular}\n",
            "\\caption{SQ3 containment by protected-asset category.}\n",
            "\\label{tab:sq3-containment-category}\n",
            "\\end{table}\n",
        ]
    )
    return "".join(lines)


def _latex_escape(text: str) -> str:
    return text.replace("_", "\\_")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the official SQ3 Layer 3 containment evaluation.")
    parser.add_argument("--out", default="results/sq3_official_containment")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--allow-missing-gvisor", action="store_true")
    parser.add_argument("--allow-missing-iptables", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    if args.preflight_only:
        report = run_official_preflight(out_dir=Path(args.out), image=args.image)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    summary = run_official_sq3(
        out_dir=Path(args.out),
        image=args.image,
        timeout=args.timeout,
        keep_artifacts=args.keep_artifacts,
        require_gvisor=not args.allow_missing_gvisor,
        require_iptables=not args.allow_missing_iptables,
    )
    print(json.dumps({k: v for k, v in summary.items() if k != "records"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
