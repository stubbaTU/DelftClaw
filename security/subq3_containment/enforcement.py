from __future__ import annotations

import json
import os
import platform
import shutil
from pathlib import Path
from typing import Any

from security.subq3_integrity.real_guardrails import run_real_guardrail_probe


def detect_enforcement_support() -> dict[str, Any]:
    return {
        "platform": platform.system(),
        "is_linux": platform.system().lower() == "linux",
        "is_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        "docker": shutil.which("docker"),
        "runsc": shutil.which("runsc"),
        "ip": shutil.which("ip"),
        "iptables": shutil.which("iptables"),
        "nft": shutil.which("nft"),
        "can_use_gvisor": platform.system().lower() == "linux"
        and shutil.which("docker") is not None
        and shutil.which("runsc") is not None,
        "can_probe_iptables_namespace": platform.system().lower() == "linux"
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
        and shutil.which("ip") is not None
        and shutil.which("iptables") is not None,
    }


def run_enforcement_preflight(out_dir: str | Path, *, timeout_s: int = 120) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    support = detect_enforcement_support()
    probe = run_real_guardrail_probe(out / "preflight", timeout_s=timeout_s)
    report = {
        "support": support,
        "probe": probe,
        "gvisor_enforced": bool(probe.get("gvisor", {}).get("ok")),
        "iptables_namespace_enforced": bool(probe.get("iptables", {}).get("ok")),
    }
    (out / "sq3_enforcement_preflight.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report

