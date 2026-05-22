"""Concise live watcher for scenario journals.

Usage:
    python -m deploy.watch_concise regtest_transfer

This is intentionally narrower than ``make watch``: it keeps the lines that
usually explain scenario progress and drops MCP transport/access-log chatter.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys


DROP_PATTERNS = (
    "Created new transport",
    "Processing request of type",
    "Negotiated protocol version",
    "Received session ID",
    "Terminating session",
    "GET stream disconnected",
    "HTTP Request: DELETE",
    "HTTP Request: GET",
    'INFO:     127.0.0.1',
)

KEEP_PATTERNS = (
    "TOOL call",
    "TOOL ok",
    "TOOL fail",
    "TOOL skip",
    "RPC error",
    "Wrong type passed",
    "wallet_send_failed",
    "openclaw agent failed",
    "openclaw_semantic_error",
    "timed out",
    "llm turn lock",
    "stop_predicate",
    "stop_predicate_satisfied",
    "IPv8 send msg=",
    "IPv8 recv msg=",
    "[boot] regtest wallet enabled",
)

TOOL_RE = re.compile(r"TOOL (?P<kind>call|ok|fail|skip)\s+name=(?P<tool>\S+).*?(?:result=(?P<result>.*))?$")
LOCK_RE = re.compile(r"\[(?P<instance>[^\]]+)\] (?P<msg>.*llm turn lock.*)")
HTTP_RPC_RE = re.compile(r'HTTP Request: POST (?P<url>http://127\.0\.0\.1:18443[^ ]*) "(?P<status>[^"]+)"')


def _agent_from_unit(unit: str, scenario: str) -> str | None:
    marker = f"@{scenario}-"
    if marker not in unit:
        return None
    return unit.split(marker, 1)[1].split(".service", 1)[0]


def _agent_from_line(line: str, scenario: str, unit: str = "") -> str:
    from_unit = _agent_from_unit(unit, scenario)
    if from_unit:
        return from_unit
    marker = f"{scenario}-"
    if marker in line:
        tail = line.split(marker, 1)[1]
        name = tail.split(".", 1)[0].split("]", 1)[0].split()[0]
        return name.strip(":")
    if "/wallet/alice" in line:
        return "alice"
    if "/wallet/bob" in line:
        return "bob"
    return "?"


def _shorten(text: str, limit: int = 220) -> str:
    text = " ".join(text.strip().split())
    return text if len(text) <= limit else text[: limit - 1] + "..."


def _format(line: str, scenario: str, unit: str = "") -> str | None:
    if any(p in line for p in DROP_PATTERNS):
        return None
    if not any(p in line for p in KEEP_PATTERNS):
        return None

    ts = " ".join(line.split()[:3])
    agent = _agent_from_line(line, scenario, unit)

    lock = LOCK_RE.search(line)
    if lock:
        return f"{ts} {lock.group('instance')} lock  {_shorten(lock.group('msg'))}"

    rpc = HTTP_RPC_RE.search(line)
    if rpc and "200 OK" not in rpc.group("status"):
        return f"{ts} {agent:5s} rpc   {rpc.group('status')} {rpc.group('url')}"

    tool = TOOL_RE.search(line)
    if tool:
        result = tool.group("result") or ""
        return f"{ts} {agent:5s} tool  {tool.group('kind'):4s} {tool.group('tool')} {_shorten(result)}"

    if "openclaw agent failed" in line:
        return f"{ts} {agent:5s} llm   {_shorten(line.split('ERROR', 1)[-1])}"

    if "IPv8 " in line:
        idx = line.find("IPv8 ")
        return f"{ts} {agent:5s} net   {_shorten(line[idx:])}"

    return f"{ts} {agent:5s} log   {_shorten(line)}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m deploy.watch_concise")
    parser.add_argument("scenario", help="scenario name, e.g. regtest_transfer")
    parser.add_argument("-n", "--lines", type=int, default=80, help="initial journal lines")
    parser.add_argument("--no-follow", action="store_true", help="print current tail and exit")
    args = parser.parse_args(argv)

    cmd = [
        "journalctl",
        "--no-pager",
        "-o",
        "json",
        "-n",
        str(args.lines),
        "-u",
        f"delftclaw-mcp@{args.scenario}-*.service",
        "-u",
        f"delftclaw-watchdog@{args.scenario}-*.service",
    ]
    if not args.no_follow:
        cmd.insert(2, "-f")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert proc.stdout is not None
    try:
        for raw_line in proc.stdout:
            raw_line = raw_line.rstrip("\n")
            unit = ""
            line = raw_line
            try:
                entry = json.loads(raw_line)
                line = str(entry.get("MESSAGE", ""))
                unit = str(entry.get("_SYSTEMD_UNIT", "") or entry.get("UNIT", ""))
            except json.JSONDecodeError:
                pass
            rendered = _format(line, args.scenario, unit)
            if rendered:
                print(rendered, flush=True)
    except KeyboardInterrupt:
        proc.terminate()
        return 130
    return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
