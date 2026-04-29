import argparse
import tempfile

from security.append_log import AppendOnlyLog
from security.reputation import ReputationEngine


def profile_harm_until_expulsion(
    threshold: int,
    malicious_events: int,
    action: str = "unauthorized_tool_execution",
) -> dict:
    """
    Measure how many malicious events are logged before reputation expels a subject.

    This is the core post-factum accountability metric from the research plan:
    the blast radius is the number of unauthorized actions observed before ban.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        log = AppendOnlyLog(log_path=f"{temp_dir}/accountability.log")
        reputation = ReputationEngine(log_path=log.log_path, ban_threshold=threshold)

        reporter_id = "honest-monitor"
        subject_id = "compromised-agent"
        expelled_after = None

        for index in range(1, malicious_events + 1):
            log.append_event(
                reporter_id=reporter_id,
                subject_id=subject_id,
                action=action,
                severity=ReputationEngine.DEFAULT_WEIGHTS.get(action, 10),
                details={"sequence": index},
            )
            reputation.scan_log()

            if reputation.is_banned(subject_id):
                expelled_after = index
                break

        integrity_ok, integrity_errors = log.verify_integrity()

        return {
            "threshold": threshold,
            "subject_id": subject_id,
            "score": reputation.get_score(subject_id),
            "harm_count": reputation.get_harm_count(subject_id),
            "expelled": reputation.is_banned(subject_id),
            "expelled_after": expelled_after,
            "integrity_ok": integrity_ok,
            "integrity_errors": integrity_errors,
        }


def main():
    parser = argparse.ArgumentParser(description="Profile OpenClaw accountability blast radius.")
    parser.add_argument("--threshold", type=int, default=10)
    parser.add_argument("--events", type=int, default=5)
    parser.add_argument(
        "--action",
        default="unauthorized_tool_execution",
        choices=[
            "unauthorized_tool_request",
            "unauthorized_tool_use",
            "unauthorized_tool_execution",
        ],
    )
    args = parser.parse_args()

    result = profile_harm_until_expulsion(
        threshold=args.threshold,
        malicious_events=args.events,
        action=args.action,
    )

    print("Accountability evaluation")
    print(f"  threshold: {result['threshold']}")
    print(f"  subject: {result['subject_id']}")
    print(f"  score: {result['score']}")
    print(f"  harm_count: {result['harm_count']}")
    print(f"  expelled: {result['expelled']}")
    print(f"  expelled_after: {result['expelled_after']}")
    print(f"  log_integrity_ok: {result['integrity_ok']}")
    if result["integrity_errors"]:
        print(f"  integrity_errors: {result['integrity_errors']}")


if __name__ == "__main__":
    main()
