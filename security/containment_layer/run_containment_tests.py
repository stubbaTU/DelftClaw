from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from security.containment_layer import CONDITION_C0, CONDITION_C1
from security.containment_layer.attack_schema import load_attacks, write_attacks
from security.containment_layer.compromised_runner import run_attack_trial
from security.containment_layer.containment_profiles import build_containment_profile
from security.containment_layer.enforcement import detect_enforcement_support, run_enforcement_preflight
from security.containment_layer.export_results import export_sq3_results
from security.containment_layer.generate_attack_suite import DEFAULT_ATTACK_PATH, generate_default_attacks
from security.containment_layer.network_guard import NetworkGuard
from security.containment_layer.protected_resources import create_protected_fixture, destroy_fixture


def run_containment_tests(
    *,
    attacks_path: Path,
    conditions: list[str],
    out_dir: Path,
    timeout: int = 10,
    use_gvisor: str = "auto",
    use_iptables: str = "auto",
    keep_artifacts: bool = False,
    preflight: bool = False,
) -> dict:
    attacks = load_attacks(attacks_path)
    results = []
    artifact_root = out_dir / "artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)

    for attack in attacks:
        for condition in conditions:
            guard = NetworkGuard.start(use_iptables=use_iptables)
            fixture = create_protected_fixture(f"{attack.attack_id}_{condition}", artifact_root)
            try:
                profile = build_containment_profile(
                    condition,
                    fixture,
                    network_guard=guard,
                    use_gvisor=use_gvisor,
                    use_iptables=use_iptables,
                )
                results.append(run_attack_trial(attack, profile, fixture, timeout_seconds=timeout))
            finally:
                guard.stop()
                if not keep_artifacts:
                    destroy_fixture(fixture)

    enforcement = {"support": detect_enforcement_support()}
    if preflight:
        enforcement["preflight"] = run_enforcement_preflight(out_dir)

    metadata = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "conditions": conditions,
        "num_attacks": len(attacks),
        "num_trials": len(results),
        "attacks_path": str(attacks_path),
        "timeout": timeout,
        "use_gvisor": use_gvisor,
        "use_iptables": use_iptables,
        "keep_artifacts": keep_artifacts,
        "safety": "local mock resources and localhost endpoints only",
        "enforcement": enforcement,
    }
    return export_sq3_results(results, out_dir, metadata)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SQ3 containment-boundary attacks.")
    parser.add_argument("--generate-attacks", action="store_true")
    parser.add_argument("--attacks", default=str(DEFAULT_ATTACK_PATH))
    parser.add_argument("--conditions", nargs="+", default=[CONDITION_C0, CONDITION_C1])
    parser.add_argument("--out", default="results/sq3_containment")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--use-gvisor", choices=["auto", "true", "false"], default="auto")
    parser.add_argument("--use-iptables", choices=["auto", "true", "false"], default="auto")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--preflight", action="store_true", help="Run real gVisor and iptables namespace probes before exporting metadata.")
    parser.add_argument("--preflight-only", action="store_true", help="Only run enforcement preflight and write sq3_enforcement_preflight.json.")
    args = parser.parse_args()

    if args.preflight_only:
        report = run_enforcement_preflight(Path(args.out))
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report.get("gvisor_enforced") and report.get("iptables_namespace_enforced") else 1

    attacks_path = Path(args.attacks)
    if args.generate_attacks or not attacks_path.exists():
        attacks = generate_default_attacks()
        write_attacks(attacks, attacks_path)

    summary = run_containment_tests(
        attacks_path=attacks_path,
        conditions=args.conditions,
        out_dir=Path(args.out),
        timeout=args.timeout,
        use_gvisor=args.use_gvisor,
        use_iptables=args.use_iptables,
        keep_artifacts=args.keep_artifacts,
        preflight=args.preflight,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
