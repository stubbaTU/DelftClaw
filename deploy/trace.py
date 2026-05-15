"""``python -m deploy.trace <scenario>`` — one-shot demo health snapshot.

Designed to replace the pile of ad-hoc ssh+jq+python one-liners that
accumulate during scenario debugging. Reads everything the operator
usually wants in a single SSH round-trip:

  * which mcp/watchdog units are up,
  * per-agent turn count + last ``openclaw_ok`` + top tool calls,
  * the last few IPv8 wire events from the journal (sent by the
    ``communication.community._log_wire`` helper),
  * a summary of each agent's community state (treasury balance,
    member count, seedbox count) if the community log is present.

Invoked from the laptop via ``make trace NAME=<scenario>`` which SSHes
to the VPS and runs ``python -m deploy.trace <scenario>``.
"""

from __future__ import annotations

import collections
import json
import subprocess
import sys
from pathlib import Path

LOG_ROOT = Path("/var/log/delftclaw/scenarios")
STATE_ROOT = Path("/var/lib/delftclaw")


# ----- colours (TTY-only) ----------------------------------------------------

def _supports_colour() -> bool:
    return sys.stdout.isatty()


_C = {
    "reset":  "\033[0m"     if _supports_colour() else "",
    "bold":   "\033[1m"     if _supports_colour() else "",
    "dim":    "\033[2m"     if _supports_colour() else "",
    "green":  "\033[1;32m"  if _supports_colour() else "",
    "red":    "\033[1;31m"  if _supports_colour() else "",
    "yellow": "\033[1;33m"  if _supports_colour() else "",
    "cyan":   "\033[1;36m"  if _supports_colour() else "",
}


def _print_header(text: str) -> None:
    print(f"\n{_C['bold']}{_C['cyan']}━━━ {text} ━━━{_C['reset']}")


# ----- systemd ---------------------------------------------------------------

def _unit_state(scenario: str) -> list[tuple[str, str]]:
    """Return ``[(unit, ActiveState)]`` for all scenario units."""
    out = subprocess.run(
        ["systemctl", "list-units",
         f"delftclaw-mcp@{scenario}-*.service",
         f"delftclaw-watchdog@{scenario}-*.service",
         "--all", "--no-pager", "--no-legend", "--plain"],
        capture_output=True, text=True,
    )
    rows: list[tuple[str, str]] = []
    for raw in out.stdout.splitlines():
        parts = raw.split()
        if len(parts) >= 4 and parts[0].startswith("delftclaw-"):
            rows.append((parts[0], parts[2]))  # unit, ActiveState
    return rows


# ----- per-agent JSONL -------------------------------------------------------

def _agents_for_scenario(scenario: str) -> list[str]:
    """Discover agent names from the scenario log directory."""
    log_dir = LOG_ROOT / scenario
    if not log_dir.is_dir():
        return []
    return sorted(p.stem for p in log_dir.glob("*.jsonl"))


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _agent_summary(scenario: str, agent: str) -> dict:
    """Compute a one-agent snapshot from its JSONL trace.

    The JSONL accumulates across runs (the log file outlives systemd
    restarts), so we anchor on the *latest* ``scenario_boot`` and only
    look at events after it. Without that, stale ``stop`` events from
    prior teardowns make every agent look stopped.
    """
    entries = _read_jsonl(LOG_ROOT / scenario / f"{agent}.jsonl")

    last_boot_idx = -1
    for i, e in enumerate(entries):
        if e.get("event") == "scenario_boot":
            last_boot_idx = i
    current_run = entries[last_boot_idx:] if last_boot_idx >= 0 else entries
    boot = entries[last_boot_idx] if last_boot_idx >= 0 else None

    turn_events = [e for e in current_run if e.get("event") == "turn"]
    stop_events = [e for e in current_run if e.get("event") == "stop"]

    last_turn = turn_events[-1] if turn_events else None
    stderr_tail = ""
    if last_turn and not last_turn.get("openclaw_ok", True):
        stderr_lines = (last_turn.get("openclaw_stderr") or "").strip().splitlines()
        stderr_tail = (stderr_lines[-1][:120] if stderr_lines else "")

    last_stdout = ""
    if last_turn:
        raw_out = (last_turn.get("openclaw_stdout") or "").strip()
        last_stdout = raw_out[:300]

    return {
        "agent_id": (boot or {}).get("agent_id", "?"),
        "stop_predicate": (boot or {}).get("stop_predicate", "?"),
        "turn_count": len(turn_events),
        "last_turn_ok": last_turn.get("openclaw_ok") if last_turn else None,
        "last_turn_n": last_turn.get("turn_n") if last_turn else None,
        "last_stop_value": last_turn.get("stop_predicate_value") if last_turn else None,
        "last_stderr_tail": stderr_tail,
        "last_stdout": last_stdout,
        "stopped": bool(stop_events),
        "total_entries_in_file": len(entries),
    }


# ----- IPv8 wire events from journal -----------------------------------------

_IPV8_MARKERS = ("IPv8 send msg=", "IPv8 recv msg=")


def _journal_lines(scenario: str, *, tail: int | None = None) -> list[str]:
    cmd = ["journalctl", "--no-pager",
           f"-u", f"delftclaw-mcp@{scenario}-*.service"]
    if tail is not None:
        cmd[2:2] = ["-n", str(tail)]
    out = subprocess.run(cmd, capture_output=True, text=True)
    return out.stdout.splitlines()


def _recent_ipv8_events(scenario: str, n: int = 20) -> list[str]:
    """Pull the last ``n`` ``IPv8 (send|recv) msg=`` lines from journalctl."""
    rows = [
        line for line in _journal_lines(scenario, tail=4000)
        if any(m in line for m in _IPV8_MARKERS)
    ]
    return rows[-n:]


def _ipv8_histogram(scenario: str) -> collections.Counter:
    """Count IPv8 msg-direction pairs across the full journal buffer.

    Matches only our own ``communication.community._log_wire`` output —
    "IPv8 send msg=Foo" / "IPv8 recv msg=Foo" — so ipv8-library startup
    chatter ("IPv8 + IPv6 dual stack...") doesn't pollute the counter.
    """
    counter: collections.Counter = collections.Counter()
    for line in _journal_lines(scenario):
        for marker in _IPV8_MARKERS:
            idx = line.find(marker)
            if idx < 0:
                continue
            direction = "send" if "send" in marker else "recv"
            # marker is "IPv8 send msg=" — everything after "msg=" up to
            # the next whitespace is the message name.
            after = line[idx + len(marker):]
            msg = after.split()[0] if after.split() else "?"
            counter[(direction, msg)] += 1
            break
    return counter


def _tool_histogram(scenario: str) -> dict[str, collections.Counter]:
    """Count ``TOOL call name=…`` lines per agent.

    Returns ``{agent_name: Counter(tool -> n)}``. Reads the journal
    rather than JSONL because the watchdog trace doesn't currently
    record individual tool calls.
    """
    per_agent: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    # Tool calls can be made by the MCP service when OpenClaw talks over MCP,
    # or directly by the watchdog when WATCHDOG_DRIVER=direct.
    out = subprocess.run(
        ["journalctl", "--no-pager", "-o", "short-iso",
         "--output-fields=UNIT,MESSAGE", "--all",
         f"-u", f"delftclaw-mcp@{scenario}-*.service",
         f"-u", f"delftclaw-watchdog@{scenario}-*.service"],
        capture_output=True, text=True,
    )
    current_unit = ""
    for line in out.stdout.splitlines():
        # Lines look like: "2026-05-15T07:30:15+0000 host UNIT[MESSAGE]"
        # but the --output-fields layout differs across systemd versions.
        # We fall back to a simpler heuristic: grep MESSAGE substring,
        # then attribute by the agent name embedded in the line if we
        # can find it.
        marker = "TOOL call name="
        idx = line.find(marker)
        if idx < 0:
            continue
        # Try to find the unit name in the line:
        agent = "?"
        for piece in line.split():
            if piece.startswith(("delftclaw-mcp@", "delftclaw-watchdog@")) and ".service" in piece:
                tag = piece.split("@", 1)[1].split(".service")[0]
                # tag is "<scenario>-<agent>"
                if "-" in tag:
                    agent = tag.split("-", 1)[1]
                break
        # Extract tool name.
        rest = line[idx + len(marker):]
        tool = rest.split()[0] if rest.split() else "?"
        # Strip a trailing "args=" if our split caught it.
        tool = tool.split("args=", 1)[0].strip() or "?"
        per_agent[agent][tool] += 1
    return per_agent


# ----- Community state -------------------------------------------------------

def _community_state_summary(scenario: str, agent: str) -> dict | None:
    """Replay an agent's community log + peer-log cache, return a state dict.

    Returns None if the logs aren't where we expect them — keeps the
    trace useful even before the first community entry is written.
    """
    try:
        from protocol.manifest import load_manifest
        from redteam.primitives.signed_log import SignedAppendOnlyLog
        from redteam.primitives.peer_log import PeerLog
        from agent.community_state import replay_community
        from identity.openclaw_identity import OpenClawIdentity
    except ImportError:
        return None

    home = STATE_ROOT / scenario / agent
    community_log = home / "community.log"
    peer_log_dir = home / "peer_logs"
    manifest_file = Path(f"/etc/delftclaw/scenarios/{scenario}-{agent}/network_manifest.md")

    if not community_log.is_file() or not manifest_file.is_file():
        return None

    try:
        manifest = load_manifest(manifest_file.read_text(encoding="utf-8"))
        # We need the agent's identity to open the SignedAppendOnlyLog.
        # That's expensive to reconstruct; instead we just count entries.
        with community_log.open("rb") as fh:
            own_entries = sum(1 for _ in fh)
        peer_entries = 0
        if peer_log_dir.is_dir():
            for p in peer_log_dir.glob("*.jsonl"):
                with p.open("rb") as fh:
                    peer_entries += sum(1 for _ in fh)
        return {
            "own_log_entries": own_entries,
            "peer_log_entries": peer_entries,
            "manifest_admission_min_sats": manifest.admission.min_sats,
            "manifest_seedbox_cost_sats": manifest.admission.seedbox_cost_sats,
        }
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


# ----- Top-level render ------------------------------------------------------

def _render_unit_state(rows: list[tuple[str, str]]) -> None:
    _print_header("systemd units")
    if not rows:
        print(f"  {_C['yellow']}(no scenario units found){_C['reset']}")
        return
    for unit, state in rows:
        colour = _C["green"] if state == "active" else (_C["red"] if state == "failed" else _C["yellow"])
        print(f"  {colour}{state:8s}{_C['reset']}  {unit}")


def _render_agent(scenario: str, agent: str, snap: dict) -> None:
    ok = snap["last_turn_ok"]
    if ok is True:
        ok_marker = f"{_C['green']}OK{_C['reset']}"
    elif ok is False:
        ok_marker = f"{_C['red']}FAIL{_C['reset']}"
    else:
        ok_marker = f"{_C['dim']}—{_C['reset']}"

    print(f"\n  {_C['bold']}{agent}{_C['reset']}  "
          f"turns_this_run={snap['turn_count']}  last_turn={snap['last_turn_n']}  "
          f"last_ok={ok_marker}  stop_pred={snap['last_stop_value']}  "
          f"stopped_this_run={'yes' if snap['stopped'] else 'no'}  "
          f"{_C['dim']}(file: {snap['total_entries_in_file']} events total){_C['reset']}")

    if snap["last_stderr_tail"]:
        print(f"    {_C['red']}stderr:{_C['reset']} {snap['last_stderr_tail']}")

    tools = snap.get("_tools", collections.Counter())
    if tools:
        print(f"    tool_calls (from journal, top 8):")
        for name, n in tools.most_common(8):
            print(f"      {n:>4}  {name}")
    else:
        print(f"    {_C['dim']}no tool calls in journal{_C['reset']}")

    if snap["last_stdout"]:
        text = snap["last_stdout"].replace("\n", " ")
        print(f"    {_C['dim']}last LLM stdout:{_C['reset']} {text}")

    cs = _community_state_summary(scenario, agent)
    if cs is not None:
        if "error" in cs:
            print(f"    {_C['dim']}community_state: {cs['error']}{_C['reset']}")
        else:
            print(f"    community: own_log={cs['own_log_entries']} entries  "
                  f"peers={cs['peer_log_entries']} entries  "
                  f"min_sats={cs['manifest_admission_min_sats']}  "
                  f"seedbox_cost={cs['manifest_seedbox_cost_sats']}")


def _render_ipv8(hist: collections.Counter, recent: list[str]) -> None:
    _print_header("IPv8 wire events — totals from journal buffer")
    if not hist:
        print(f"  {_C['yellow']}(none yet — no IPv8 traffic logged){_C['reset']}")
    else:
        for (direction, msg), n in sorted(hist.items(), key=lambda kv: -kv[1]):
            print(f"  {n:>5}  {direction:4s}  {msg}")

    _print_header("IPv8 wire events — last 15")
    if not recent:
        print(f"  {_C['dim']}(empty){_C['reset']}")
    else:
        for line in recent[-15:]:
            # Strip the journal prefix ``May 15 07:30:15 srv1665973 python[NNN]:``
            try:
                i = line.index("IPv8 ")
                print(f"  {line[i:]}")
            except ValueError:
                print(f"  {line}")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m deploy.trace <scenario>", file=sys.stderr)
        return 2
    scenario = argv[1]

    rows = _unit_state(scenario)
    _render_unit_state(rows)

    agents = _agents_for_scenario(scenario)
    tools_by_agent = _tool_histogram(scenario)
    _print_header(f"agents in {scenario}")
    if not agents:
        print(f"  {_C['yellow']}(no JSONL traces found under {LOG_ROOT / scenario}){_C['reset']}")
    else:
        for agent in agents:
            snap = _agent_summary(scenario, agent)
            snap["_tools"] = tools_by_agent.get(agent, collections.Counter())
            _render_agent(scenario, agent, snap)

    _render_ipv8(_ipv8_histogram(scenario), _recent_ipv8_events(scenario))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
