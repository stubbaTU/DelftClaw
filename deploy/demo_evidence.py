"""Export a presentation-friendly evidence bundle for a finished scenario.

Usage on the VPS:

    PYTHONPATH=/opt/delftclaw /opt/delftclaw/venv/bin/python \
      -m deploy.demo_evidence secure_community_demo

The exporter keeps the existing JSONL logs intact and creates a separate
bundle with:

  * demo_trace.txt: the same concise output as ``deploy.trace`` for screenshots
  * github_comment.md: short update text to paste into GitHub
  * agent_logs/*.jsonl: full per-agent turn logs
  * security_evidence.json / real_guardrails.json when present
  * demo_evidence_bundle.zip containing the same files
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any


LOG_ROOT = Path("/var/log/delftclaw/scenarios")
STATE_ROOT = Path("/var/lib/delftclaw")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _run_trace(scenario: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-m", "deploy.trace", scenario],
        capture_output=True,
        text=True,
    )
    text = proc.stdout
    if proc.stderr:
        text += "\n\n[stderr]\n" + proc.stderr
    return text


def _status(value: Any) -> str:
    return "OK" if bool(value) else "WAIT"


def _github_comment(scenario: str, trace_text: str, evidence: dict[str, Any]) -> str:
    integrated = evidence.get("integrated_story") or {}
    checklist = evidence.get("checklist") or {}
    story_ok = bool(integrated.get("represented") or checklist.get("integrated"))
    subject = integrated.get("subject_id", "agent_2")
    target = (integrated.get("target_secret") or {}).get(
        "asset",
        "local OpenClaw identity private signing key",
    )
    accountability = integrated.get("accountability") or {}
    impact = integrated.get("impact") or {}
    real = impact.get("real_guardrails") or {}
    gvisor = real.get("gvisor") or {}
    iptables = real.get("iptables") or {}

    return "\n".join([
        "## Secure community demo update",
        "",
        "I ran the integrated four-agent secure community demo on the VPS.",
        "",
        "What the run demonstrates:",
        "- Four autonomous OpenClaw agents form the community, donate to join, exchange Creative Commons content over IPv8, and trigger the second seedbox.",
        f"- After the community expansion, `{subject}` becomes the compromised member and attempts to expose its own `{target}`.",
        "- Brain-vs-Hands blocks the private-key probe and the privileged iptables bypass attempt.",
        f"- Signed accountability lowers trust, raises risk to `{accountability.get('risk_after_more_malicious_behavior')}`, and expels the compromised agent.",
        f"- Containment evidence shows proxy isolation passed: `{impact.get('with_proxy_only_isolation_passed')}`, gVisor passed: `{gvisor.get('ok')}`, iptables passed: `{iptables.get('ok')}`.",
        "",
        f"Overall integrated security outcome: **{_status(story_ok)}**",
        "",
        "Attached evidence:",
        "- `demo_trace.txt` contains the concise operator trace used for the screenshot.",
        "- `agent_logs/` contains the full per-agent JSONL turn logs.",
        "- `security_evidence.json` contains the structured security episode evidence.",
        "- `demo_evidence_bundle.zip` contains the complete exported bundle.",
        "",
        "<details>",
        "<summary>Latest trace excerpt</summary>",
        "",
        "```text",
        _tail_interesting_trace(trace_text),
        "```",
        "",
        "</details>",
        "",
    ])


def _tail_interesting_trace(trace_text: str) -> str:
    markers = (
        "━━━ community story checklist ━━━",
        "━━━ integrated security episode ━━━",
        "━━━ IPv8 wire events",
    )
    lines = trace_text.splitlines()
    start = 0
    for idx, line in enumerate(lines):
        if any(marker in line for marker in markers):
            start = idx
            break
    return "\n".join(lines[start:])[-6000:]


def export_demo_evidence(scenario: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)

    trace_text = _run_trace(scenario)
    (out_dir / "demo_trace.txt").write_text(trace_text, encoding="utf-8")

    log_dir = LOG_ROOT / scenario
    agent_logs = out_dir / "agent_logs"
    agent_logs.mkdir(exist_ok=True)
    if log_dir.is_dir():
        for path in sorted(log_dir.glob("*.jsonl")):
            shutil.copy2(path, agent_logs / path.name)

    security_dir = STATE_ROOT / scenario / "security"
    evidence_path = security_dir / "security_evidence.json"
    real_guardrails_path = security_dir / "real_guardrails.json"
    evidence = _read_json(evidence_path)
    if evidence_path.is_file():
        shutil.copy2(evidence_path, out_dir / "security_evidence.json")
    if real_guardrails_path.is_file():
        shutil.copy2(real_guardrails_path, out_dir / "real_guardrails.json")

    metadata = {
        "scenario": scenario,
        "exported_at_unix": time.time(),
        "log_dir": str(log_dir),
        "security_dir": str(security_dir),
    }
    (out_dir / "export_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (out_dir / "github_comment.md").write_text(
        _github_comment(scenario, trace_text, evidence),
        encoding="utf-8",
    )

    zip_path = out_dir / "demo_evidence_bundle.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(out_dir.rglob("*")):
            if path == zip_path or path.is_dir():
                continue
            archive.write(path, path.relative_to(out_dir))
    return out_dir


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m deploy.demo_evidence")
    parser.add_argument("scenario", help="scenario name, e.g. secure_community_demo")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output directory; default: /var/lib/delftclaw/<scenario>/github_update",
    )
    args = parser.parse_args()

    out_dir = args.out or STATE_ROOT / args.scenario / "github_update"
    export_demo_evidence(args.scenario, out_dir)
    print(f"wrote evidence bundle to {out_dir}")
    print(f"pasteable comment: {out_dir / 'github_comment.md'}")
    print(f"zip bundle: {out_dir / 'demo_evidence_bundle.zip'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
