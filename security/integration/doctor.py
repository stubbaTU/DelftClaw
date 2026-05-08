from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from security.integration.client import DelftClawClient


def run_checks(base_url: str, agent_id: str, include_attack: bool = True) -> dict[str, Any]:
    client = DelftClawClient(base_url=base_url, agent_id=agent_id, timeout=10)
    checks: list[dict[str, Any]] = []

    health = client._get("/health")
    checks.append(_check("health", health.get("ok") is True, health))

    status = client.openclaw_status()
    checks.append(_check("openclaw_status", "enabled" in status, status))

    message = client.send_message("peer", "hello from DelftClaw doctor", payload_id="doctor_send_message")
    checks.append(
        _check(
            "allowed_send_message",
            message.get("ok") is True and message.get("blocked") is False,
            message,
        )
    )

    if include_attack:
        blocked = client.tool_call(
            "exfiltrate_private_key",
            {"payload": "doctor should be blocked"},
            payload_id="doctor_forbidden_tool",
            source="doctor",
        )
        result = blocked.get("result", {})
        checks.append(
            _check(
                "forbidden_tool_blocked",
                blocked.get("ok") is False
                and blocked.get("blocked") is True
                and result.get("executed") is False,
                blocked,
            )
        )

    metrics = client.metrics()
    checks.append(
        _check(
            "metrics_integrity",
            metrics.get("integrity_ok") is True,
            metrics,
        )
    )

    return {
        "ok": all(item["ok"] for item in checks),
        "base_url": base_url,
        "agent_id": agent_id,
        "checks": checks,
    }


def print_text(report: dict[str, Any]) -> None:
    print(f"DelftClaw doctor: {'PASS' if report['ok'] else 'FAIL'}")
    print(f"  base_url: {report['base_url']}")
    print(f"  agent_id: {report['agent_id']}")
    for check in report["checks"]:
        marker = "PASS" if check["ok"] else "FAIL"
        print(f"  {marker} {check['name']}")
        if not check["ok"]:
            print(json.dumps(check["response"], indent=2, sort_keys=True))


def _check(name: str, ok: bool, response: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "ok": ok, "response": response}


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a running DelftClaw gateway.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8765", help="Gateway base URL.")
    parser.add_argument("--agent-id", default="doctor-agent", help="Agent id used for test calls.")
    parser.add_argument("--skip-attack", action="store_true", help="Skip the forbidden-tool blocking check.")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON.")
    args = parser.parse_args()

    report = run_checks(
        base_url=args.base_url,
        agent_id=args.agent_id,
        include_attack=not args.skip_attack,
    )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text(report)

    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
