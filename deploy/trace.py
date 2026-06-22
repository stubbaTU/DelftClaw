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
        "last_snapshot": last_turn.get("snapshot") if last_turn else None,
        "stop_snapshot": stop_events[-1].get("snapshot") if stop_events else None,
        "stopped": bool(stop_events),
        "total_entries_in_file": len(entries),
    }


# ----- IPv8 wire events from journal -----------------------------------------

_IPV8_MARKERS = ("IPv8 send msg=", "IPv8 recv msg=")


def _journal_lines(scenario: str, *, tail: int | None = None) -> list[str]:
    cmd = ["journalctl", "--no-pager",
           f"-u", f"delftclaw-mcp@{scenario}-*.service",
           f"-u", f"delftclaw-watchdog@{scenario}-*.service"]
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
    # Tool calls are made by the MCP service when OpenClaw talks to it over MCP.
    #
    # ``-o with-unit`` is load-bearing here. The previous incantation
    # (``-o short-iso --output-fields=UNIT,MESSAGE``) silently dropped the
    # unit name from each line — ``--output-fields`` is ignored unless the
    # format is verbose/export/json — so the per-line unit-name lookup below
    # always failed, every call landed under ``agent="?"``, and the renderer
    # printed "no tool calls in journal" even when the MCP service was
    # dispatching dozens of calls per turn.
    out = subprocess.run(
        ["journalctl", "--no-pager", "-o", "with-unit", "--all",
         f"-u", f"delftclaw-mcp@{scenario}-*.service",
         f"-u", f"delftclaw-watchdog@{scenario}-*.service"],
        capture_output=True, text=True,
    )
    for line in out.stdout.splitlines():
        marker = "TOOL call name="
        idx = line.find(marker)
        if idx < 0:
            continue
        # Lines now look like:
        #   2026-05-29T08:01:25+0000 host delftclaw-mcp@<scenario>-<agent>.service[pid]: ... TOOL call name=…
        agent = "?"
        for piece in line.split():
            if piece.startswith(("delftclaw-mcp@", "delftclaw-watchdog@")) and ".service" in piece:
                tag = piece.split("@", 1)[1].split(".service")[0]
                # tag is "<scenario>-<agent>"
                if "-" in tag:
                    agent = tag.split("-", 1)[1]
                break
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
                  f"min_sats={cs['manifest_admission_min_sats']}")


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


# ----- Overlay lifecycle (compile/install) from journal ----------------------

_OVERLAY_MARKER = "OVERLAY "


def _parse_kv_tokens(tokens: list[str]) -> dict[str, str]:
    """``["cid=ab", "result=ok"]`` -> ``{"cid": "ab", "result": "ok"}``."""
    out: dict[str, str] = {}
    for tok in tokens:
        if "=" in tok:
            key, value = tok.split("=", 1)
            out[key] = value
    return out


def _recent_overlay_events(scenario: str, n: int = 20) -> list[str]:
    """Last ``n`` ``OVERLAY compile|install …`` lines from the journal."""
    rows = [
        line for line in _journal_lines(scenario, tail=4000)
        if _OVERLAY_MARKER in line and ("compile cid=" in line or "install cid=" in line)
    ]
    return rows[-n:]


def _overlay_lifecycle_histogram(scenario: str) -> collections.Counter:
    """Count overlay lifecycle events from the journal.

    Keys: ``("compile", "ok"|"fail")``, ``("install", "")`` and
    ``("src", "cache_hit"|"llm")`` — matches the ``protocol.registry``
    ``delftclaw.overlay.lifecycle`` stream only.
    """
    counter: collections.Counter = collections.Counter()
    for line in _journal_lines(scenario):
        idx = line.find(_OVERLAY_MARKER)
        if idx < 0:
            continue
        toks = line[idx + len(_OVERLAY_MARKER):].split()
        if not toks or toks[0] not in ("compile", "install"):
            continue
        event = toks[0]
        kv = _parse_kv_tokens(toks[1:])
        if event == "compile":
            counter[("compile", kv.get("result", "?"))] += 1
            if "src" in kv:
                counter[("src", kv["src"])] += 1
        else:
            counter[("install", "")] += 1
    return counter


def _render_overlay_lifecycle(hist: collections.Counter, recent: list[str]) -> None:
    _print_header("overlay lifecycle — compile/install (from journal)")
    if not hist:
        print(f"  {_C['yellow']}(none yet — no markdown-as-overlay compiles logged){_C['reset']}")
    else:
        ok = hist.get(("compile", "ok"), 0)
        fail = hist.get(("compile", "fail"), 0)
        inst = hist.get(("install", ""), 0)
        cache_hit = hist.get(("src", "cache_hit"), 0)
        llm = hist.get(("src", "llm"), 0)
        caller = hist.get(("src", "caller"), 0)
        fail_colour = _C["red"] if fail else _C["green"]
        # ``caller`` source = the seeder-publish path that hands the registry
        # a pre-canned ``*_stub.py`` body via ``llm_source=``. Skipping it on
        # display undercounted the v2 install lifecycle by exactly the seeder
        # contribution.
        print(f"  compile: {_C['green']}{ok} ok{_C['reset']}, {fail_colour}{fail} fail{_C['reset']}   "
              f"install: {inst}   source: {cache_hit} cache_hit / {llm} llm / {caller} caller")

    _print_header("overlay lifecycle — last 15")
    if not recent:
        print(f"  {_C['dim']}(empty){_C['reset']}")
    else:
        for line in recent[-15:]:
            try:
                i = line.index("OVERLAY ")
                print(f"  {line[i:]}")
            except ValueError:
                print(f"  {line}")


# ----- Overlay versions (per-demo content-addressed spec archive) ------------

def _overlay_archive_dir(scenario: str, agent: str) -> Path:
    return STATE_ROOT / scenario / agent / "overlay_archive"


def _agents_with_archive(scenario: str) -> list[str]:
    base = STATE_ROOT / scenario
    if not base.is_dir():
        return []
    return sorted(p.parent.name for p in base.glob("*/overlay_archive") if p.is_dir())


def _overlay_versions(scenario: str, agents: list[str]) -> tuple[dict, list[str]]:
    """Group archived specs by community_id across agents; detect genuine drift.

    Returns ``(by_cid, drift)`` where ``by_cid[cid] = {name, version, holders,
    provenance, supersedes, author_id, change_summary}``.

    ``drift`` distinguishes intentional evolution from corruption. Two cids for
    one overlay name are NOT drift when they form a ``supersedes`` chain (one's
    meta points at the other) — that's a deliberate version bump and renders as
    a chain. Genuine drift is two coexisting cids for one name with NO
    supersedes link between any of them — i.e. agents silently diverged.
    """
    by_cid: dict[str, dict] = {}
    for agent in agents:
        adir = _overlay_archive_dir(scenario, agent)
        if not adir.is_dir():
            continue
        for meta_path in sorted(adir.glob("*.meta.json")):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            # Compile-fail and post-compile-stranded cids leave a meta.json
            # behind (the archive writes one on every ``seen`` event) but with
            # empty name/identity_version. Surfacing them here as ``(unknown)
            # v?`` rows pollutes the "overlay versions" view; the lifecycle
            # totals and overlay ledger sections still expose them as failures
            # so the data is preserved, just relocated to the right section.
            if not meta.get("name") or not meta.get("identity_version"):
                continue
            cid = meta.get("community_id_hex") or meta_path.name.split(".")[0]
            entry = by_cid.setdefault(cid, {
                "name": "", "version": "", "holders": set(), "provenance": [],
                "supersedes": None, "author_id": "", "change_summary": "",
            })
            entry["holders"].add(agent)
            entry["name"] = entry["name"] or meta.get("name", "")
            entry["version"] = entry["version"] or meta.get("identity_version", "")
            entry["supersedes"] = entry["supersedes"] or meta.get("supersedes")
            entry["author_id"] = entry["author_id"] or meta.get("author_id", "")
            entry["change_summary"] = entry["change_summary"] or meta.get("change_summary", "")
            for prov in meta.get("provenance", []) or []:
                tag = prov.get("tag") if isinstance(prov, dict) else str(prov)
                if tag:
                    entry["provenance"].append(f"{agent}:{tag}")

    names_to_cids: dict[str, set] = collections.defaultdict(set)
    for cid, entry in by_cid.items():
        if entry["name"]:
            names_to_cids[entry["name"]].add(cid)

    drift: list[str] = []
    for name, cids in names_to_cids.items():
        if len(cids) <= 1:
            continue
        # Evolution if at least one cid supersedes another present cid (a chain
        # links them). Drift if the coexisting cids share no supersedes edge.
        linked = any(
            by_cid[c]["supersedes"] in cids for c in cids if by_cid[c]["supersedes"]
        )
        if not linked:
            drift.append(
                f"{name}: {len(cids)} unlinked community_ids "
                f"({', '.join(sorted(c[:12] for c in cids))}) — no supersedes chain"
            )
    return by_cid, drift


def _version_chains(by_cid: dict) -> dict[str, list[str]]:
    """Order cids per overlay name into supersedes chains (oldest → newest).

    Returns ``{name: [cid_oldest, ..., cid_newest]}``. A cid whose ``supersedes``
    points at another present cid comes after it. Cids with no present
    predecessor are roots; unlinked siblings of one name (drift) just appear in
    name+version order.
    """
    by_name: dict[str, list[str]] = collections.defaultdict(list)
    for cid, e in by_cid.items():
        by_name[e["name"]].append(cid)
    chains: dict[str, list[str]] = {}
    for name, cids in by_name.items():
        present = set(cids)
        succ = {c: by_cid[c]["supersedes"] for c in cids}
        roots = [c for c in cids if not succ[c] or succ[c] not in present]
        ordered: list[str] = []
        # Walk forward from each root following "who supersedes me".
        reverse: dict[str, list[str]] = collections.defaultdict(list)
        for c in cids:
            if succ[c] in present:
                reverse[succ[c]].append(c)
        seen: set[str] = set()
        stack = sorted(roots, key=lambda c: by_cid[c]["version"])
        while stack:
            c = stack.pop(0)
            if c in seen:
                continue
            seen.add(c)
            ordered.append(c)
            stack = sorted(reverse.get(c, []), key=lambda x: by_cid[x]["version"]) + stack
        # Any cids not reached (cycles / oddities) appended deterministically.
        ordered += [c for c in sorted(cids) if c not in seen]
        chains[name] = ordered
    return chains


def _overlay_ledger_tail(scenario: str, agents: list[str], n: int = 12) -> list[str]:
    rows: list[tuple] = []
    for agent in agents:
        ledger = _overlay_archive_dir(scenario, agent) / "overlay_ledger.jsonl"
        for rec in _read_jsonl(ledger):
            rows.append((rec.get("ts", 0), agent, rec))
    rows.sort(key=lambda r: r[0])
    out = []
    for _ts, agent, rec in rows[-n:]:
        bits = [
            f"{agent}:",
            rec.get("event", "?"),
            f"cid={str(rec.get('community_id_hex', ''))[:12]}",
        ]
        if rec.get("name"):
            bits.append(f"name={rec['name']}")
        if rec.get("identity_version"):
            bits.append(f"v={rec['identity_version']}")
        if rec.get("provenance"):
            bits.append(f"prov={rec['provenance']}")
        if rec.get("stage"):
            bits.append(f"stage={rec['stage']}")
        out.append(" ".join(bits))
    return out


def _render_overlay_versions(scenario: str) -> None:
    agents = _agents_with_archive(scenario)
    by_cid, drift = _overlay_versions(scenario, agents)
    _print_header("overlay versions — per-demo spec archive")
    if not by_cid:
        print(f"  {_C['dim']}(no overlay archive under {STATE_ROOT}/{scenario}/*/overlay_archive){_C['reset']}")
        return

    chains = _version_chains(by_cid)
    for name in sorted(chains):
        cids = chains[name]
        for i, cid in enumerate(cids):
            entry = by_cid[cid]
            holders = ", ".join(sorted(entry["holders"]))
            arrow = f"{_C['cyan']}↳ supersedes {entry['supersedes'][:12]}{_C['reset']} " if entry["supersedes"] else ""
            author = f" author={entry['author_id'][:18]}" if entry["author_id"] else ""
            print(f"  {_C['bold']}{name or '(unknown)'}{_C['reset']} "
                  f"v{entry['version'] or '?'}  cid={cid[:12]}  held_by=[{holders}]{author}")
            if arrow:
                print(f"    {arrow}")
            if entry["change_summary"]:
                print(f"    {_C['dim']}\"{entry['change_summary']}\"{_C['reset']}")
            if entry["provenance"]:
                print(f"    {_C['dim']}provenance: {'; '.join(entry['provenance'][:6])}{_C['reset']}")

    if drift:
        for line in drift:
            print(f"  {_C['red']}DRIFT{_C['reset']} {line}")
    else:
        multi = any(len(c) > 1 for c in chains.values())
        if multi:
            print(f"  {_C['green']}no drift{_C['reset']} — coexisting versions are linked by supersedes (intentional evolution)")
        else:
            print(f"  {_C['green']}no spec drift{_C['reset']} — each overlay name maps to a single community_id")

    # Evolution timeline: authored events across all agents, oldest first.
    authored = _overlay_authored_events(scenario, agents)
    if authored:
        _print_header("overlay evolution — authored events")
        for line in authored:
            print(f"  {line}")

    tail = _overlay_ledger_tail(scenario, agents)
    if tail:
        _print_header("overlay ledger — last events")
        for line in tail:
            print(f"  {line}")


def _overlay_authored_events(scenario: str, agents: list[str]) -> list[str]:
    """Every ``authored`` ledger event across agents, chronological.

    These mark the exact moment an agent introduced a protocol version — the
    agentic protocol-evolution act, distinct from adopters' ``install`` events.
    """
    rows: list[tuple] = []
    for agent in agents:
        ledger = _overlay_archive_dir(scenario, agent) / "overlay_ledger.jsonl"
        for rec in _read_jsonl(ledger):
            if rec.get("event") != "authored":
                continue
            rows.append((rec.get("ts", 0), agent, rec))
    rows.sort(key=lambda r: r[0])
    out = []
    for _ts, agent, rec in rows:
        bits = [
            f"{_C['bold']}{agent}{_C['reset']} authored",
            f"{rec.get('name', '?')} v{rec.get('identity_version', '?')}",
            f"cid={str(rec.get('community_id_hex', ''))[:12]}",
        ]
        if rec.get("supersedes"):
            bits.append(f"supersedes={str(rec['supersedes'])[:12]}")
        if rec.get("author_id"):
            bits.append(f"author={str(rec['author_id'])[:18]}")
        line = "  ".join(bits)
        if rec.get("change_summary"):
            line += f'\n      {_C["dim"]}"{rec["change_summary"]}"{_C["reset"]}'
        out.append(line)
    return out


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
    summaries: dict[str, dict] = {}
    if not agents:
        print(f"  {_C['yellow']}(no JSONL traces found under {LOG_ROOT / scenario}){_C['reset']}")
    else:
        for agent in agents:
            snap = _agent_summary(scenario, agent)
            snap["_tools"] = tools_by_agent.get(agent, collections.Counter())
            summaries[agent] = snap
            _render_agent(scenario, agent, snap)

    _render_ipv8(_ipv8_histogram(scenario), _recent_ipv8_events(scenario))
    _render_overlay_lifecycle(
        _overlay_lifecycle_histogram(scenario), _recent_overlay_events(scenario)
    )
    _render_overlay_versions(scenario)
    _render_version_history(scenario)
    return 0


def _render_version_history(scenario: str) -> None:
    """Inline the fleet-merged version_history.md artifact.

    The on-disk artifact is the source of truth for the thesis writeup
    (committed by ``OverlayArchive.append_authored_event`` every time any
    agent in the scenario publishes a spec). We just read + print it so the
    operator sees the same thing the bundle will contain.
    """
    history_dir = STATE_ROOT / scenario
    md_path = history_dir / "version_history.md"
    _print_header("version history — fleet-merged (per scenario)")
    if not md_path.is_file():
        print(f"  {_C['dim']}(no version_history.md yet at {md_path}){_C['reset']}")
        return
    try:
        text = md_path.read_text(encoding="utf-8").rstrip()
    except OSError as exc:
        print(f"  {_C['red']}failed to read {md_path}: {exc}{_C['reset']}")
        return
    for line in text.splitlines():
        print(f"  {line}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
