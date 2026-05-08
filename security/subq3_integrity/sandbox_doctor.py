from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
from pathlib import Path
from typing import Any

from security.subq2_accountability.append_log import AppendOnlyLog


def run_sandbox_checks(manifest_path: str | Path, *, require_gvisor: bool = False) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))

    host_log_path = Path(manifest["host_log_path"])
    host_secret_path = Path(manifest["host_secret_path"])
    iptables_rules_path = Path(manifest["iptables_rules_path"])
    sandbox_workspace = Path(manifest["sandbox_workspace"])
    prompt_path = Path(manifest["prompt_path"])
    artifacts_dir = Path(manifest["sandbox_artifacts_dir"])
    baseline_hashes = manifest.get("baseline_hashes") or {}

    checks = []
    checks.append(_check("manifest_exists", manifest_file.exists(), {"manifest_path": str(manifest_file)}))
    checks.append(_check("host_log_exists", host_log_path.exists(), {"path": str(host_log_path)}))
    checks.append(_check("host_secret_exists", host_secret_path.exists(), {"path": str(host_secret_path)}))
    checks.append(_check("iptables_fixture_exists", iptables_rules_path.exists(), {"path": str(iptables_rules_path)}))
    checks.append(_check("sandbox_workspace_exists", sandbox_workspace.exists(), {"path": str(sandbox_workspace)}))
    checks.append(_check("filled_prompt_exists", prompt_path.exists(), {"path": str(prompt_path)}))
    checks.append(_check("gvisor_artifacts_exist", (artifacts_dir / "Dockerfile.gvisor").exists(), {"path": str(artifacts_dir)}))

    if host_log_path.exists():
        integrity_ok, integrity_errors = AppendOnlyLog(str(host_log_path)).verify_integrity()
        checks.append(_check("host_log_integrity", integrity_ok, {"errors": integrity_errors}))

    checks.append(
        _check(
            "host_paths_outside_sandbox_workspace",
            all(not _is_relative_to(path, sandbox_workspace) for path in (host_log_path, host_secret_path, iptables_rules_path)),
            {
                "trusted_host_paths": [str(host_log_path), str(host_secret_path), str(iptables_rules_path)],
                "sandbox_workspace": str(sandbox_workspace),
            },
        )
    )

    current_hashes = {
        "host_log_sha256": _file_hash(host_log_path) if host_log_path.exists() else "",
        "host_secret_sha256": _file_hash(host_secret_path) if host_secret_path.exists() else "",
        "iptables_rules_sha256": _file_hash(iptables_rules_path) if iptables_rules_path.exists() else "",
    }
    checks.append(
        _check(
            "baseline_hashes_match",
            all(current_hashes.get(key) == baseline_hashes.get(key) for key in baseline_hashes),
            {"baseline_hashes": baseline_hashes, "current_hashes": current_hashes},
        )
    )

    docker_path = shutil.which("docker")
    runsc_path = shutil.which("runsc")
    linux = platform.system().lower() == "linux"
    checks.append(_check("linux_host_ready", linux or not require_gvisor, {"platform": platform.system()}))
    checks.append(_check("docker_available", docker_path is not None or not require_gvisor, {"docker": docker_path or ""}))
    checks.append(_check("runsc_available", runsc_path is not None or not require_gvisor, {"runsc": runsc_path or ""}))

    return {
        "ok": all(item["ok"] for item in checks),
        "manifest_path": str(manifest_file),
        "run_id": manifest.get("run_id", ""),
        "condition": manifest.get("condition", ""),
        "checks": checks,
    }


def print_text(report: dict[str, Any]) -> None:
    print(f"DelftClaw SubQ3 sandbox doctor: {'PASS' if report['ok'] else 'FAIL'}")
    print(f"  manifest: {report['manifest_path']}")
    print(f"  run_id: {report['run_id']}")
    print(f"  condition: {report['condition']}")
    for check in report["checks"]:
        marker = "PASS" if check["ok"] else "FAIL"
        print(f"  {marker} {check['name']}")
        if not check["ok"]:
            print(json.dumps(check["details"], indent=2, sort_keys=True))


def _check(name: str, ok: bool, details: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "ok": ok, "details": details}


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify SubQ3 sandbox workspace before running integrity experiments.")
    parser.add_argument("--manifest", required=True, help="Path to subq3_manifest.json.")
    parser.add_argument("--require-gvisor", action="store_true", help="Fail if runsc is not available.")
    parser.add_argument("--json", action="store_true", help="Print full JSON report.")
    args = parser.parse_args()

    report = run_sandbox_checks(args.manifest, require_gvisor=args.require_gvisor)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text(report)
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
