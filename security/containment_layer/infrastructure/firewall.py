from __future__ import annotations

import shutil
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


NFT_TABLE = "vukzero_sq3"


@dataclass(frozen=True)
class FirewallBackend:
    name: str
    docker_backend: str
    iptables_version: str
    nft_version: str
    notes: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "docker_backend": self.docker_backend,
            "iptables_version": self.iptables_version,
            "nft_version": self.nft_version,
            "notes": self.notes,
        }


def detect_firewall_backend() -> FirewallBackend:
    docker_backend = _cmd_text(["docker", "info", "--format", "{{.FirewallBackend}}"])
    iptables_version = _cmd_text(["iptables", "--version"]) if shutil.which("iptables") else ""
    nft_version = _cmd_text(["nft", "--version"]) if shutil.which("nft") else ""
    if shutil.which("nft"):
        return FirewallBackend(
            name="native_nftables",
            docker_backend=docker_backend,
            iptables_version=iptables_version,
            nft_version=nft_version,
            notes="Dedicated inet vukzero_sq3 table; Docker chains are not edited.",
        )
    if "(nf_tables)" in iptables_version:
        return FirewallBackend(
            name="iptables_nf_tables",
            docker_backend=docker_backend,
            iptables_version=iptables_version,
            nft_version=nft_version,
            notes="iptables compatibility interface backed by nf_tables.",
        )
    return FirewallBackend(
        name="unavailable",
        docker_backend=docker_backend,
        iptables_version=iptables_version,
        nft_version=nft_version,
        notes="No supported nftables enforcement backend detected.",
    )


@contextmanager
def egress_filter(
    backend: FirewallBackend,
    *,
    container_ip: str,
    gateway_ip: str,
    allowed_peer_port: int,
    out_dir: Path,
    artifact_label: str = "",
) -> Iterator[None]:
    if backend.name == "native_nftables":
        with _native_nft_filter(
            container_ip=container_ip,
            gateway_ip=gateway_ip,
            allowed_peer_port=allowed_peer_port,
            out_dir=out_dir,
            artifact_label=artifact_label,
        ):
            yield
        return
    if backend.name == "iptables_nf_tables":
        with _iptables_nft_filter(
            container_ip=container_ip,
            gateway_ip=gateway_ip,
            allowed_peer_port=allowed_peer_port,
            out_dir=out_dir,
            artifact_label=artifact_label,
        ):
            yield
        return
    raise RuntimeError("no supported nftables firewall backend is available")


@contextmanager
def _native_nft_filter(
    *,
    container_ip: str,
    gateway_ip: str,
    allowed_peer_port: int,
    out_dir: Path,
    artifact_label: str,
) -> Iterator[None]:
    script = f"""table inet {NFT_TABLE} {{
  chain input {{
    type filter hook input priority -10; policy accept;
    ip saddr {container_ip} ip daddr {gateway_ip} tcp dport {allowed_peer_port} accept
    ip saddr {container_ip} ip daddr {gateway_ip} reject
  }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    ip saddr {container_ip} reject
  }}
}}
"""
    _delete_native_table()
    subprocess.run(["nft", "-f", "-"], input=script, text=True, check=True, capture_output=True)
    _write_nft_snapshot(out_dir / _artifact_name("sq3_nft_ruleset", artifact_label, ".txt"))
    try:
        yield
    finally:
        _delete_native_table()


@contextmanager
def _iptables_nft_filter(
    *,
    container_ip: str,
    gateway_ip: str,
    allowed_peer_port: int,
    out_dir: Path,
    artifact_label: str,
) -> Iterator[None]:
    insert_rules = [
        ["iptables", "-I", "INPUT", "1", "-s", container_ip, "-d", gateway_ip, "-p", "tcp", "--dport", str(allowed_peer_port), "-j", "ACCEPT"],
        ["iptables", "-I", "INPUT", "2", "-s", container_ip, "-d", gateway_ip, "-j", "REJECT"],
        ["iptables", "-I", "DOCKER-USER", "1", "-s", container_ip, "-j", "REJECT"],
    ]
    delete_rules = [
        ["iptables", "-D", "INPUT", "-s", container_ip, "-d", gateway_ip, "-p", "tcp", "--dport", str(allowed_peer_port), "-j", "ACCEPT"],
        ["iptables", "-D", "INPUT", "-s", container_ip, "-d", gateway_ip, "-j", "REJECT"],
        ["iptables", "-D", "DOCKER-USER", "-s", container_ip, "-j", "REJECT"],
    ]
    for rule in insert_rules:
        subprocess.run(rule, check=True, capture_output=True, text=True)
    _write_iptables_snapshot(out_dir / _artifact_name("sq3_iptables_ruleset", artifact_label, ".txt"))
    _write_nft_snapshot(out_dir / _artifact_name("sq3_nft_ruleset", artifact_label, ".txt"))
    try:
        yield
    finally:
        for rule in reversed(delete_rules):
            subprocess.run(rule, check=False, capture_output=True, text=True)


def _delete_native_table() -> None:
    subprocess.run(
        ["nft", "delete", "table", "inet", NFT_TABLE],
        check=False,
        capture_output=True,
        text=True,
    )


def _write_nft_snapshot(path: Path) -> None:
    if shutil.which("nft") is None:
        path.write_text("nft binary unavailable; iptables-nft backend used\n", encoding="utf-8")
        return
    proc = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, check=False)
    path.write_text(proc.stdout + proc.stderr, encoding="utf-8")


def _write_iptables_snapshot(path: Path) -> None:
    if shutil.which("iptables-save") is None:
        path.write_text("iptables-save unavailable\n", encoding="utf-8")
        return
    proc = subprocess.run(["iptables-save"], capture_output=True, text=True, check=False)
    path.write_text(proc.stdout + proc.stderr, encoding="utf-8")


def _cmd_text(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return (proc.stdout + proc.stderr).strip()


def _artifact_name(stem: str, label: str, suffix: str) -> str:
    return f"{stem}_{label}{suffix}" if label else f"{stem}{suffix}"
