from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from security.contracts import SecurityAction
from security.datasets.payloads import load_payloads
from security.integration.openclaw_tools import TOOL_REGISTRY, tool_manifest
from security.subq1_preventative.privilege import BaselineExecutor, Hands
from security.subq2_accountability.reputation import ReputationEngine
from security.subq3_integrity.gvisor_artifacts import generate_artifacts


def run_security_readiness(*, artifact_dir: str | Path | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    malicious = load_payloads("security/datasets/malicious_torrent_payloads.jsonl")
    benign = load_payloads("security/datasets/benign_torrent_payloads.jsonl")
    checks.append(_check("subq1_malicious_payloads_loaded", len(malicious) > 0, {"count": len(malicious)}))
    checks.append(_check("subq1_benign_payloads_loaded", len(benign) > 0, {"count": len(benign)}))

    default_tools = Hands.default_tools()
    checks.append(
        _check(
            "subq1_private_key_tool_guarded",
            "exfiltrate_private_key" not in default_tools,
            {"tools": sorted(default_tools)},
        )
    )
    dangerous_tools = BaselineExecutor.default_dangerous_tools()
    checks.append(
        _check(
            "subq1_baseline_contains_private_key_attack_tool",
            "exfiltrate_private_key" in dangerous_tools,
            {"dangerous_tools": sorted(dangerous_tools)},
        )
    )

    required_actions = {
        SecurityAction.ATOMIC_MICROTASK_CLAIMED.value,
        SecurityAction.ATOMIC_MICROTASK_VERIFIED.value,
        SecurityAction.ATOMIC_MICROTASK_REJECTED.value,
        SecurityAction.WASH_TRADE_DETECTED.value,
        SecurityAction.PRIVATE_KEY_EXFILTRATION.value,
        SecurityAction.IPTABLES_MODIFICATION_ATTEMPT.value,
    }
    missing_weights = sorted(action for action in required_actions if action not in ReputationEngine.DEFAULT_WEIGHTS)
    checks.append(_check("subq2_reputation_weights_complete", not missing_weights, {"missing": missing_weights}))

    manifest_names = {spec["name"] for spec in tool_manifest(include_experiment_only=True)}
    required_tools = {
        "delftclaw_register_seedbox",
        "delftclaw_broadcast_seedbox_donation",
        "delftclaw_submit_seedbox_proof",
        "delftclaw_submit_atomic_microtask",
        "delftclaw_verify_atomic_microtask",
        "delftclaw_report_security_event",
        "delftclaw_get_metrics",
        "delftclaw_get_reputation",
        "delftclaw_run_blocking_probe",
    }
    missing_tools = sorted(required_tools - manifest_names)
    checks.append(_check("openclaw_security_tools_complete", not missing_tools, {"missing": missing_tools}))
    checks.append(
        _check(
            "normal_tool_registry_matches_manifest",
            set(TOOL_REGISTRY) == {spec["name"] for spec in tool_manifest()},
            {"registry": sorted(TOOL_REGISTRY)},
        )
    )

    artifacts = None
    if artifact_dir is not None:
        target = Path(artifact_dir)
        generate_artifacts(target)
        artifacts = {
            "dockerfile": str(target / "Dockerfile.gvisor"),
            "iptables": str(target / "iptables_sandbox.sh"),
            "runbook": str(target / "README.md"),
        }
        checks.append(
            _check(
                "subq3_artifacts_generated",
                all(Path(path).exists() for path in artifacts.values()),
                artifacts,
            )
        )

    return {
        "ok": all(check["ok"] for check in checks),
        "checks": checks,
        "artifact_dir": str(artifact_dir) if artifact_dir is not None else "",
        "artifacts": artifacts,
    }


def _check(name: str, ok: bool, details: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "ok": ok, "details": details}


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Check that security infrastructure is ready to wire into identity/communication.")
    parser.add_argument("--artifact-dir", help="Optional directory where SQ3 gVisor/iptables artifacts should be generated.")
    parser.add_argument("--json", action="store_true", help="Print JSON report.")
    args = parser.parse_args()

    report = run_security_readiness(artifact_dir=args.artifact_dir)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"DelftClaw security readiness: {'PASS' if report['ok'] else 'FAIL'}")
        for check in report["checks"]:
            print(f"  {'PASS' if check['ok'] else 'FAIL'} {check['name']}")
            if not check["ok"]:
                print(json.dumps(check["details"], indent=2, sort_keys=True))

    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
