from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from security.integration.doctor import run_checks
from security.integration.gateway import load_env_file
from security.integration.openclaw_tools import TOOL_REGISTRY, tool_manifest
from security.subq2_accountability.append_log import AppendOnlyLog


def run_infrastructure_checks(
    *,
    env_path: str | Path,
    check_gateway: bool = True,
    include_attack: bool = True,
) -> dict[str, Any]:
    env_values = load_env_file(str(env_path))
    base_url = env_values.get("DELFTCLAW_GATEWAY_URL", "http://127.0.0.1:8765")
    agent_id = env_values.get("DELFTCLAW_AGENT_ID", "doctor-agent")
    log_path = Path(env_values.get("DELFTCLAW_LOG_PATH", "logs/template.jsonl"))
    experiment_root = Path(env_values.get("DELFTCLAW_EXPERIMENT_ROOT", "real_experiment_workdir"))
    run_id = env_values.get("DELFTCLAW_RUN_ID", "")
    condition = env_values.get("DELFTCLAW_EXPERIMENT_CONDITION", "")

    checks: list[dict[str, Any]] = []
    checks.append(_check("env_file_exists", Path(env_path).exists(), {"env_path": str(env_path)}))
    checks.append(_check("run_id_configured", bool(run_id), {"run_id": run_id}))
    checks.append(_check("condition_configured", bool(condition), {"condition": condition}))
    checks.append(_check("normal_tool_registry_not_empty", bool(TOOL_REGISTRY), {"tools": sorted(TOOL_REGISTRY)}))

    manifest_names = {spec["name"] for spec in tool_manifest()}
    checks.append(
        _check(
            "manifest_matches_registry",
            manifest_names == set(TOOL_REGISTRY),
            {"manifest": sorted(manifest_names), "registry": sorted(TOOL_REGISTRY)},
        )
    )

    canary_manifest = experiment_root / "canary_manifest.json"
    responses_dir = experiment_root / "responses"
    checks.append(
        _check(
            "experiment_root_exists",
            experiment_root.exists(),
            {"experiment_root": str(experiment_root), "hint": "run setup_canaries.py if this fails"},
        )
    )
    checks.append(
        _check(
            "canary_manifest_exists",
            canary_manifest.exists(),
            {"canary_manifest": str(canary_manifest), "hint": "run setup_canaries.py if this fails"},
        )
    )
    checks.append(
        _check(
            "responses_dir_exists",
            responses_dir.exists(),
            {"responses_dir": str(responses_dir), "hint": "run setup_canaries.py if this fails"},
        )
    )

    if log_path.exists():
        integrity_ok, integrity_errors = AppendOnlyLog(str(log_path)).verify_integrity()
        entries = AppendOnlyLog(str(log_path)).read_entries()
        run_metadata_count = sum(1 for entry in entries if entry.get("run_id") or entry.get("experiment_condition"))
        checks.append(_check("log_integrity", integrity_ok, {"log_path": str(log_path), "errors": integrity_errors}))
        checks.append(
            _check(
                "log_has_run_metadata_or_empty",
                len(entries) == 0 or run_metadata_count > 0,
                {"log_path": str(log_path), "entry_count": len(entries), "run_metadata_entries": run_metadata_count},
            )
        )
    else:
        checks.append(
            _check(
                "log_path_parent_exists",
                log_path.parent.exists(),
                {"log_path": str(log_path), "hint": "gateway creates the log file when it starts"},
            )
        )

    gateway_report = None
    if check_gateway:
        gateway_report = run_checks(base_url=base_url, agent_id=agent_id, include_attack=include_attack)
        checks.append(_check("gateway_doctor", gateway_report.get("ok") is True, gateway_report))

    return {
        "ok": all(item["ok"] for item in checks),
        "env_path": str(env_path),
        "base_url": base_url,
        "agent_id": agent_id,
        "log_path": str(log_path),
        "experiment_root": str(experiment_root),
        "run_id": run_id,
        "condition": condition,
        "checks": checks,
        "gateway_report": gateway_report,
    }


def print_text(report: dict[str, Any]) -> None:
    print(f"DelftClaw infrastructure doctor: {'PASS' if report['ok'] else 'FAIL'}")
    print(f"  env: {report['env_path']}")
    print(f"  gateway: {report['base_url']}")
    print(f"  run_id: {report['run_id'] or '<missing>'}")
    print(f"  condition: {report['condition'] or '<missing>'}")
    for check in report["checks"]:
        marker = "PASS" if check["ok"] else "FAIL"
        print(f"  {marker} {check['name']}")
        if not check["ok"]:
            print(json.dumps(check["details"], indent=2, sort_keys=True))


def _check(name: str, ok: bool, details: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "ok": ok, "details": details}


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify DelftClaw infrastructure before running real experiments.")
    parser.add_argument("--env", required=True, help="Local DelftClaw env file.")
    parser.add_argument("--skip-gateway", action="store_true", help="Only check local files/config/tool registry.")
    parser.add_argument("--skip-attack", action="store_true", help="Skip the gateway forbidden-tool blocking check.")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON.")
    args = parser.parse_args()

    report = run_infrastructure_checks(
        env_path=args.env,
        check_gateway=not args.skip_gateway,
        include_attack=not args.skip_attack,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text(report)

    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
