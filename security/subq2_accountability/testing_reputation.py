import argparse
import os
import tempfile
from pathlib import Path

from security.results import accountability_row, write_csv, write_json
from security.subq2_accountability.accountability import AccountabilityMetrics, run_reputation_trap_experiment


def compare_accountability(
    malicious_actions: int,
    threshold: int,
    scan_interval: int,
) -> tuple[AccountabilityMetrics, AccountabilityMetrics]:
    """
    Run the exact sub-question 2 comparison:

    1. No accountability: harmful actions continue until the fixed run ends.
    2. Accountability: harmful actions stop once reputation expels the subject.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        no_accountability = run_reputation_trap_experiment(
            accountability_enabled=False,
            total_malicious_actions=malicious_actions,
            threshold=threshold,
            scan_interval=scan_interval,
            log_path=os.path.join(temp_dir, "no_accountability.log"),
        )
        accountability = run_reputation_trap_experiment(
            accountability_enabled=True,
            total_malicious_actions=malicious_actions,
            threshold=threshold,
            scan_interval=scan_interval,
            log_path=os.path.join(temp_dir, "accountability.log"),
        )

    return no_accountability, accountability


def fallout_reduction(no_accountability: AccountabilityMetrics, accountability: AccountabilityMetrics) -> float:
    if no_accountability.fallout_radius == 0:
        return 0.0
    prevented = no_accountability.fallout_radius - accountability.fallout_radius
    return prevented / no_accountability.fallout_radius


def harm_reduction(no_accountability: AccountabilityMetrics, accountability: AccountabilityMetrics) -> float:
    return fallout_reduction(no_accountability, accountability)


def export_results(export_dir: str | None, no_accountability: AccountabilityMetrics, accountability: AccountabilityMetrics):
    if not export_dir:
        return

    target = Path(export_dir)
    rows = [
        accountability_row("no_accountability", no_accountability),
        accountability_row("accountability_enabled", accountability),
    ]
    write_csv(target / "subq2_reputation_trap_results.csv", rows)
    write_json(
        target / "subq2_reputation_trap_results.json",
        {
            "fallout_reduction": fallout_reduction(no_accountability, accountability),
            "rows": rows,
        },
    )


def print_metrics(label: str, metrics: AccountabilityMetrics):
    print(label)
    print(f"  accountability_enabled: {metrics.accountability_enabled}")
    print(f"  attempted_actions: {metrics.attempted_actions}")
    print(f"  unauthorized_executions: {metrics.unauthorized_executions}")
    print(f"  fake_donations: {metrics.fake_donations}")
    print(f"  honest_transactions_stolen: {metrics.honest_transactions_stolen}")
    print(f"  wash_trades_detected: {metrics.wash_trades_detected}")
    print(f"  fallout_radius: {metrics.fallout_radius}")
    print(f"  reputation_lag: {metrics.reputation_lag}")
    print(f"  blocked_actions: {metrics.blocked_actions}")
    print(f"  final_score: {metrics.final_score}")
    print(f"  expelled: {metrics.expelled}")
    print(f"  expulsion_step: {metrics.expulsion_step}")
    print(f"  log_integrity_ok: {metrics.integrity_ok}")
    if metrics.integrity_errors:
        print(f"  integrity_errors: {metrics.integrity_errors}")


def main():
    parser = argparse.ArgumentParser(description="Compare Reputation Trap fallout with and without accountability.")
    parser.add_argument("--actions", type=int, default=10, help="Total rug-pull imposter actions attempted by the subject.")
    parser.add_argument("--threshold", type=int, default=30, help="Reputation score required for expulsion.")
    parser.add_argument("--scan-interval", type=int, default=1, help="How often reputation scans the log.")
    parser.add_argument("--export-dir", help="Optional directory for CSV/JSON experiment outputs.")
    args = parser.parse_args()

    no_accountability, accountability = compare_accountability(
        malicious_actions=args.actions,
        threshold=args.threshold,
        scan_interval=args.scan_interval,
    )

    print("Reputation Trap accountability evaluation")
    print(f"  rug_pull_imposter_attempts: {args.actions}")
    print(f"  threshold: {args.threshold}")
    print(f"  scan_interval: {args.scan_interval}")
    print_metrics("No accountability", no_accountability)
    print_metrics("Accountability enabled", accountability)
    print(f"Fallout reduction: {fallout_reduction(no_accountability, accountability):.2%}")
    export_results(args.export_dir, no_accountability, accountability)


if __name__ == "__main__":
    main()
