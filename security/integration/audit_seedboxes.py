from __future__ import annotations

import argparse
import json
import time
from typing import Any

from security.integration.client import DelftClawClient


def run_audit(
    *,
    base_url: str | None = None,
    agent_id: str | None = None,
    interval_seconds: float = 0,
    max_iterations: int = 1,
) -> list[dict[str, Any]]:
    client = DelftClawClient(base_url=base_url, agent_id=agent_id)
    reports = []
    iteration = 0

    while max_iterations <= 0 or iteration < max_iterations:
        iteration += 1
        report = client.audit_seedboxes()
        reports.append({"iteration": iteration, "report": report})
        if max_iterations > 0 and iteration >= max_iterations:
            break
        time.sleep(interval_seconds)

    return reports


def main() -> None:
    parser = argparse.ArgumentParser(description="Run DelftClaw seedbox audits once or on an interval.")
    parser.add_argument("--base-url", default=None, help="Gateway base URL. Defaults to DELFTCLAW_GATEWAY_URL.")
    parser.add_argument("--agent-id", default=None, help="Agent id. Defaults to DELFTCLAW_AGENT_ID.")
    parser.add_argument("--interval-seconds", type=float, default=0, help="Delay between audit iterations.")
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=1,
        help="Number of audits to run. Use 0 for an infinite loop.",
    )
    args = parser.parse_args()

    if args.max_iterations <= 0 and args.interval_seconds <= 0:
        raise SystemExit("--interval-seconds must be greater than 0 when --max-iterations is 0")

    reports = run_audit(
        base_url=args.base_url,
        agent_id=args.agent_id,
        interval_seconds=args.interval_seconds,
        max_iterations=args.max_iterations,
    )
    print(json.dumps(reports, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
