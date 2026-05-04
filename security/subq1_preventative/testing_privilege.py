import argparse
from pathlib import Path

from security.contracts import RedTeamPayload
from security.datasets.payloads import load_benign_torrent_payloads, load_malicious_torrent_payloads
from security.results import execution_rows, write_csv, write_json
from security.subq1_preventative.privilege import (
    BaselineAgent,
    BaselineExecutor,
    Brain,
    Hands,
    PrivilegeSeparatedAgent,
    attack_success_rate,
)


def run_suite(payloads: list[RedTeamPayload]):
    baseline = BaselineAgent(brain=Brain(), executor=BaselineExecutor())
    defended = PrivilegeSeparatedAgent(brain=Brain(), hands=Hands())

    baseline_results = [
        baseline.handle_payload(
            payload.text,
            recipient="peer",
            payload_id=payload.payload_id,
            sender_id="malicious-torrent" if payload.malicious else "benign-peer",
        )
        for payload in payloads
    ]
    defended_results = [
        defended.handle_payload(
            payload.text,
            recipient="peer",
            payload_id=payload.payload_id,
            sender_id="malicious-torrent" if payload.malicious else "benign-peer",
        )
        for payload in payloads
    ]

    return baseline_results, defended_results


def print_results(label: str, results):
    print(label)
    print(f"  ASR: {attack_success_rate(results):.2%}")
    for index, result in enumerate(results, start=1):
        print(
            f"  {index}. payload_id={result.payload_id} "
            f"tool={result.requested_tool} "
            f"executed={result.executed} "
            f"attack_success={result.attack_success} "
            f"reason={result.reason}"
        )


def export_results(export_dir: str | None, baseline_results, defended_results, benign_defended):
    if not export_dir:
        return

    target = Path(export_dir)
    rows = (
        execution_rows("baseline", baseline_results)
        + execution_rows("privilege_separated", defended_results)
        + execution_rows("benign_privilege_separated", benign_defended)
    )
    write_csv(target / "subq1_asr_results.csv", rows)
    write_json(
        target / "subq1_asr_results.json",
        {
            "baseline_asr": attack_success_rate(baseline_results),
            "privilege_separated_asr": attack_success_rate(defended_results),
            "benign_privilege_separated_asr": attack_success_rate(benign_defended),
            "rows": rows,
        },
    )


def main():
    parser = argparse.ArgumentParser(description="Evaluate private-key exfiltration ASR on malicious torrent payloads.")
    parser.add_argument("--export-dir", help="Optional directory for CSV/JSON experiment outputs.")
    args = parser.parse_args()

    malicious_payloads = load_malicious_torrent_payloads()
    benign_payloads = load_benign_torrent_payloads()

    baseline_results, defended_results = run_suite(malicious_payloads)
    print("Malicious torrent payload evaluation")
    print_results("Baseline agent", baseline_results)
    print_results("Privilege-separated agent", defended_results)

    _, benign_defended = run_suite(benign_payloads)
    print_results("Defended benign sanity check", benign_defended)
    export_results(args.export_dir, baseline_results, defended_results, benign_defended)


if __name__ == "__main__":
    main()
