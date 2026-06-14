from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from security.containment_layer.infrastructure.firewall import detect_firewall_backend
from security.containment_layer.infrastructure.runtimes import RUNTIMES


def detect_enforcement_support() -> dict[str, Any]:
    """
    Probe the system for the presence of various enforcement mechanisms.
    """
    firewall = detect_firewall_backend()
    return {
        "platform": platform.system(),
        "kernel_version": platform.release(),
        "is_linux": platform.system().lower() == "linux",
        "is_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        "docker": shutil.which("docker"),
        "runc": shutil.which("runc"),
        "runsc": shutil.which("runsc"),
        "nft": shutil.which("nft"),
        "iptables": shutil.which("iptables"),
        "apparmor_parser": shutil.which("apparmor_parser"),
        "registered_runtimes": _json_cmd(["docker", "info", "--format", "{{json .Runtimes}}"]),
        "firewall_backend": firewall.to_dict(),
        "gvisor_platform": RUNTIMES["runsc"].gvisor_platform,
        "runc_version": _cmd_text(["runc", "--version"]),
        "runsc_version": _cmd_text(["runsc", "--version"]),
        "docker_security_options": _cmd_text(["docker", "info", "--format", "{{json .SecurityOptions}}"]),
        "can_use_gvisor": platform.system().lower() == "linux"
        and shutil.which("docker") is not None
        and shutil.which("runsc") is not None,
        "can_probe_iptables_namespace": platform.system().lower() == "linux"
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
        and shutil.which("ip") is not None
        and shutil.which("iptables") is not None,
    }


def write_enforcement_inventory(out_dir: str | Path) -> dict[str, Any]:
    """
    Dump the results of the enforcement probe to a JSON file.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report = detect_enforcement_support()
    (out / "sq3_enforcement_inventory.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _cmd_text(cmd: list[str]) -> str:
    if shutil.which(cmd[0]) is None:
        return ""
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return (proc.stdout + proc.stderr).strip()


def _json_cmd(cmd: list[str]) -> dict[str, Any]:
    value = _cmd_text(cmd)
    try:
        result = json.loads(value)
        return result if isinstance(result, dict) else {}
    except json.JSONDecodeError:
        return {}
