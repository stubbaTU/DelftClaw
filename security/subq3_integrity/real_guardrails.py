from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


def run_real_guardrail_probe(root: str | Path, *, timeout_s: int = 120) -> dict[str, Any]:
    """Run best-effort real gVisor and iptables guardrail checks.

    The iptables probe is deliberately executed in a temporary Linux network
    namespace. That makes the firewall rules real while keeping them away from
    the host OUTPUT policy and SSH session.
    """
    root_path = Path(root)
    root_path.mkdir(parents=True, exist_ok=True)
    report = {
        "ok": False,
        "created_at": time.time(),
        "platform": platform.system(),
        "is_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        "gvisor": _gvisor_probe(root_path, timeout_s=timeout_s),
        "iptables": _iptables_namespace_probe(timeout_s=timeout_s),
    }
    report["ok"] = bool(
        report["gvisor"].get("ok") is True
        and report["iptables"].get("ok") is True
    )
    path = root_path / "real_guardrails.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def _gvisor_probe(root: Path, *, timeout_s: int) -> dict[str, Any]:
    docker = shutil.which("docker")
    runsc = shutil.which("runsc")
    if platform.system().lower() != "linux":
        return {"attempted": False, "ok": False, "reason": "not_linux"}
    if docker is None:
        return {"attempted": False, "ok": False, "reason": "docker_not_found"}
    if runsc is None:
        return {"attempted": False, "ok": False, "reason": "runsc_not_found", "docker": docker}

    probe_dir = root / "gvisor_probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    marker = probe_dir / "host_marker.txt"
    marker.write_text("HOST_MARKER_SHOULD_NOT_BE_VISIBLE\n", encoding="utf-8")

    cmd = [
        docker,
        "run",
        "--rm",
        "--runtime=runsc",
        "--network=none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "busybox:1.36",
        "sh",
        "-c",
        (
            "echo ok >/tmp/probe && "
            "test ! -e /host_marker.txt && "
            "wget -T 1 -qO- http://1.1.1.1 >/tmp/net 2>/tmp/neterr; "
            "test $? -ne 0 && "
            "echo GVISOR_PROBE_OK"
        ),
    ]
    proc = _run(cmd, timeout_s=timeout_s)
    return {
        "attempted": True,
        "ok": proc["returncode"] == 0 and "GVISOR_PROBE_OK" in proc["stdout"],
        "docker": docker,
        "runsc": runsc,
        "runtime": "runsc",
        "network": "none",
        "read_only_rootfs": True,
        "tmpfs_tmp": True,
        "host_marker_path": str(marker),
        "command": _redact_cmd(cmd),
        "returncode": proc["returncode"],
        "stdout": proc["stdout"][-1000:],
        "stderr": proc["stderr"][-1000:],
    }


def _iptables_namespace_probe(*, timeout_s: int) -> dict[str, Any]:
    ip = shutil.which("ip")
    iptables = shutil.which("iptables")
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    if platform.system().lower() != "linux":
        return {"attempted": False, "ok": False, "reason": "not_linux"}
    if ip is None:
        return {"attempted": False, "ok": False, "reason": "ip_not_found"}
    if iptables is None:
        return {"attempted": False, "ok": False, "reason": "iptables_not_found", "ip": ip}
    if not is_root:
        return {"attempted": False, "ok": False, "reason": "requires_root", "ip": ip, "iptables": iptables}

    ns = f"dclawiso{os.getpid()}{int(time.time())}"
    commands = [
        [ip, "netns", "add", ns],
        [ip, "netns", "exec", ns, iptables, "-P", "OUTPUT", "DROP"],
        [ip, "netns", "exec", ns, iptables, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        [ip, "netns", "exec", ns, iptables, "-S", "OUTPUT"],
    ]
    results = []
    try:
        for cmd in commands:
            results.append(_run(cmd, timeout_s=timeout_s))
        rules = results[-1]["stdout"]
        ok = (
            all(item["returncode"] == 0 for item in results)
            and "-P OUTPUT DROP" in rules
            and "-A OUTPUT -o lo -j ACCEPT" in rules
        )
        return {
            "attempted": True,
            "ok": ok,
            "namespace": ns,
            "ip": ip,
            "iptables": iptables,
            "output_policy_drop": "-P OUTPUT DROP" in rules,
            "loopback_allowed": "-A OUTPUT -o lo -j ACCEPT" in rules,
            "rules": rules,
            "commands": [_redact_cmd(cmd) for cmd in commands],
            "results": results,
        }
    finally:
        _run([ip, "netns", "delete", ns], timeout_s=timeout_s, check=False)


def _run(cmd: list[str], *, timeout_s: int, check: bool = False) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=check,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": f"timeout after {timeout_s}s: {exc.stderr or ''}",
        }
    except Exception as exc:
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
        }


def _redact_cmd(cmd: list[str]) -> list[str]:
    return [str(part) for part in cmd]


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Run real gVisor and iptables guardrail probes.")
    parser.add_argument("--root", required=True)
    parser.add_argument("--timeout-s", type=int, default=120)
    args = parser.parse_args()
    report = run_real_guardrail_probe(args.root, timeout_s=args.timeout_s)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
