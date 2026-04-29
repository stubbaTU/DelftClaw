import argparse
import os
import tempfile

from security.accountability import AccountabilityMetrics, run_harm_until_expulsion_experiment


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
        no_accountability = run_harm_until_expulsion_experiment(
            accountability_enabled=False,
            total_malicious_actions=malicious_actions,
            threshold=threshold,
            scan_interval=scan_interval,
            log_path=os.path.join(temp_dir, "no_accountability.log"),
        )
        accountability = run_harm_until_expulsion_experiment(
            accountability_enabled=True,
            total_malicious_actions=malicious_actions,
            threshold=threshold,
            scan_interval=scan_interval,
            log_path=os.path.join(temp_dir, "accountability.log"),
        )

    return no_accountability, accountability


def harm_reduction(no_accountability: AccountabilityMetrics, accountability: AccountabilityMetrics) -> float:
    if no_accountability.blast_radius == 0:
        return 0.0
    prevented = no_accountability.blast_radius - accountability.blast_radius
    return prevented / no_accountability.blast_radius


def print_metrics(label: str, metrics: AccountabilityMetrics):
    print(label)
    print(f"  accountability_enabled: {metrics.accountability_enabled}")
    print(f"  attempted_actions: {metrics.attempted_actions}")
    print(f"  unauthorized_executions: {metrics.unauthorized_executions}")
    print(f"  blast_radius: {metrics.blast_radius}")
    print(f"  blocked_actions: {metrics.blocked_actions}")
    print(f"  final_score: {metrics.final_score}")
    print(f"  expelled: {metrics.expelled}")
    print(f"  expulsion_step: {metrics.expulsion_step}")
    print(f"  log_integrity_ok: {metrics.integrity_ok}")
    if metrics.integrity_errors:
        print(f"  integrity_errors: {metrics.integrity_errors}")


def main():
    parser = argparse.ArgumentParser(description="Compare harm until expulsion with and without accountability.")
    parser.add_argument("--actions", type=int, default=10, help="Total malicious actions attempted by the subject.")
    parser.add_argument("--threshold", type=int, default=30, help="Reputation score required for expulsion.")
    parser.add_argument("--scan-interval", type=int, default=1, help="How often reputation scans the log.")
    args = parser.parse_args()

    no_accountability, accountability = compare_accountability(
        malicious_actions=args.actions,
        threshold=args.threshold,
        scan_interval=args.scan_interval,
    )

    print("Game-theoretic accountability evaluation")
    print(f"  malicious_actions: {args.actions}")
    print(f"  threshold: {args.threshold}")
    print(f"  scan_interval: {args.scan_interval}")
    print_metrics("No accountability", no_accountability)
    print_metrics("Accountability enabled", accountability)
    print(f"Harm reduction: {harm_reduction(no_accountability, accountability):.2%}")


if __name__ == "__main__":
    main()
