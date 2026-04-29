import argparse
import platform
import shutil
import tempfile

from security.subq3_integrity.integrity import LogIntegrityExperimentResult, run_log_integrity_experiment


def gvisor_status() -> tuple[bool, str]:
    if platform.system().lower() != "linux":
        return False, "gVisor/runsc is Linux-only for this experiment; current platform is not Linux."

    runsc_path = shutil.which("runsc")
    if runsc_path is None:
        return False, "runsc was not found on PATH."

    return True, f"runsc found at {runsc_path}"


def print_result(result: LogIntegrityExperimentResult):
    print(result.mode)
    print(f"  host_log_path_exposed: {result.host_log_path_exposed}")
    print(f"  passed: {result.passed}")
    print(f"  successful_attacks: {result.successful_attacks}")
    for attempt in result.attempts:
        print(
            f"  - {attempt.attack_name}: "
            f"succeeded={attempt.succeeded} "
            f"host_log_changed={attempt.host_log_changed} "
            f"host_log_deleted={attempt.host_log_deleted} "
            f"integrity_ok={attempt.integrity_ok}"
        )
        if attempt.error:
            print(f"    error: {attempt.error}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate append-only log integrity before OpenClaw integration.")
    parser.add_argument(
        "--show-gvisor-status",
        action="store_true",
        help="Print whether this machine is ready to run the later gVisor/runsc isolation test.",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as temp_dir:
        host_dir = f"{temp_dir}/host"
        workspace_dir = f"{temp_dir}/agent_workspace"
        no_isolation, proxy_only = run_log_integrity_experiment(
            host_dir=host_dir,
            workspace_dir=workspace_dir,
        )

    print("Log integrity evaluation")
    print_result(no_isolation)
    print_result(proxy_only)

    if args.show_gvisor_status:
        available, message = gvisor_status()
        print("gVisor readiness")
        print(f"  available: {available}")
        print(f"  message: {message}")


if __name__ == "__main__":
    main()
