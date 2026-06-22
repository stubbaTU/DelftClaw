"""Per-agent autonomous watchdog loop.

Run by ``delftclaw-watchdog@<scenario>-<agent>.service`` once the matching
MCP server is up. The watchdog:

  1. Reads the scenario manifest + this agent's persona/goal markdown.
  2. Boots its OWN OpenClawAgent in-process (separate IPv8 instance from
     the MCP server — same identity though, so peers see one entity).
  3. Every ``interval_s`` seconds: collects a state snapshot, evaluates
     the stop predicate, builds a turn prompt, invokes ``openclaw agent``
     as a subprocess.
  4. Logs each turn to ``<log_dir>/<agent>.jsonl`` (one JSON object per line).
  5. Exits cleanly when the stop predicate fires, a cap is hit, or N
     consecutive LLM errors happen.

Exit codes (meaningful — surfaced by systemd):
  0 — stop predicate satisfied
  1 — max_total_turns reached without satisfying predicate
  2 — max_wall_clock_s reached
  3 — N consecutive openclaw-agent invocation failures

Usage:
    python -m deploy.watchdog --instance <scenario>-<agent> \\
        --scenario-dir /etc/delftclaw/scenarios/<scenario>-<agent>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from agent.runtime import AgentConfig, OpenClawAgent
from communication.bittorrent import build_default_service
from deploy import stop_predicates
from deploy.scenario import AgentSpec, parse_scenario
from deploy.state_snapshot import collect_state
from deploy.turn_builder import (
    TurnHistory,
    TurnRecord,
    build_turn_prompt,
    turn_cap_reached,
    wall_clock_exceeded,
)
from identity.agent_identity import AgentIdentity
from identity.seed import KeyfileSeedSource
from protocol.llm import OpenAICompatibleClient
from agent.cli import (
    _apply_seed_content,
    _publish_overlays,
    is_publish_overlay_sentinel,
)
from agent.wake_signal import read_signal_mtime, self_state_dir


_log = logging.getLogger("watchdog")

EXIT_OK = 0
EXIT_TURNS_EXHAUSTED = 1
EXIT_WALL_CLOCK = 2
EXIT_LLM_ERRORS = 3

MAX_CONSECUTIVE_LLM_ERRORS = 5

# Minimum delay between consecutive turns FOR THE SAME AGENT, in seconds.
# Independent of ``interval_s`` (the per-tick cap): a peer's wake signal can
# shorten the wait below ``interval_s`` but never below ``MIN_FLOOR_S``. The
# floor exists so an LLM that mis-fires can't churn budget / quota at the
# polling cadence — 60s comfortably covers a real-Haiku overlay compile so a
# successful turn isn't competing with its own previous turn's lingering work.
MIN_FLOOR_S = 60.0

# Polling granularity of the wake-watching sleep. ≤2s loss vs ideal early
# wake; the GIL/asyncio cost of a stat() every 2s is negligible.
WAKE_POLL_S = 2.0


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

def _split_instance(instance: str) -> tuple[str, str]:
    """``"<scenario>-<agent>"`` -> (scenario, agent). Agents may not contain ``-``."""
    if "-" not in instance:
        raise SystemExit(f"watchdog: --instance {instance!r} must be '<scenario>-<agent>'")
    scenario, agent = instance.split("-", 1)
    return scenario, agent


def _resolve_manifest(scenario_dir: Path, scenario_name: str) -> Path:
    candidate = scenario_dir / "scenario.yaml"
    if candidate.is_file():
        return candidate
    # Fall back to the repo's deploy/scenarios/<name>/scenario.yaml for dev runs.
    repo_default = Path(__file__).resolve().parent / "scenarios" / scenario_name / "scenario.yaml"
    if repo_default.is_file():
        return repo_default
    raise SystemExit(f"watchdog: scenario.yaml not found ({candidate} or {repo_default})")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class JsonlSink:
    """Append-only JSONL writer with ``fsync`` for safety."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: dict[str, Any]) -> None:
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


# ---------------------------------------------------------------------------
# OpenClaw subprocess
# ---------------------------------------------------------------------------

def _reset_openclaw_session(instance: str) -> None:
    """Wipe the per-instance OpenClaw session dir so the next ``openclaw
    agent`` call starts a fresh conversation.

    OpenClaw maintains session state across invocations under
    ``$HOME/.openclaw/agents/<instance>/sessions/``. Without resetting,
    every watchdog tick appends to the same session — within ~10 turns
    that overruns the model's context window and every subsequent turn
    fails with "Context overflow: prompt too large".

    Removing the sessions directory is robust against openclaw CLI flag
    changes; openclaw recreates the dir on the next invocation.
    """
    home = os.environ.get("HOME")
    if not home:
        return
    sessions_dir = Path(home) / ".openclaw" / "agents" / instance / "sessions"
    if not sessions_dir.exists():
        return
    try:
        for child in sessions_dir.iterdir():
            if child.is_file():
                child.unlink(missing_ok=True)
            elif child.is_dir():
                import shutil
                shutil.rmtree(child, ignore_errors=True)
    except Exception as exc:
        _log.warning("failed to wipe %s: %s (context may overflow eventually)",
                     sessions_dir, exc)


def _invoke_openclaw_agent(
    *,
    instance: str,
    prompt: str,
    timeout_s: int,
) -> tuple[bool, str, str]:
    """Run ``openclaw agent --local --agent <instance> --message <prompt>``.

    ``--local`` skips OpenClaw's WebSocket gateway daemon (which we don't
    run on the VPS) and uses the embedded agent path instead. The model
    is configured when ``scenario_boot.py`` registers the OpenClaw agent
    with ``openclaw agents add --model ...``.

    Returns ``(ok, stdout, stderr)``. ``ok`` is True iff the subprocess
    exited 0 within timeout.
    """
    # Reset the session BEFORE every call so context doesn't accumulate
    # across watchdog ticks. The agent re-reads the full state snapshot
    # each turn anyway — there's nothing in session history a fresh start
    # actually loses for our use case.
    _reset_openclaw_session(instance)

    # ``--thinking off`` for non-reasoning model configs (some reject any
    # other level). If/when this watchdog drives a reasoning model, expose
    # ``thinking`` via the env file.
    cmd = [
        "openclaw", "agent",
        "--local",
        "--agent", instance,
        "--message", prompt,
        "--json",
        "--timeout", str(timeout_s),
        "--thinking", "off",
    ]
    # env.copy() already carries LLM_API_KEY (from the systemd EnvironmentFile),
    # which is the apiKey OpenClaw's config resolves against.
    env = os.environ.copy()
    env["PATH"] = env.get("PATH") or "/usr/local/bin:/usr/bin:/bin"
    env.setdefault("OPENCLAW_DISABLE_TELEMETRY", "1")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 30,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return False, "", f"openclaw timed out after {timeout_s + 30}s: {exc}"
    return proc.returncode == 0, proc.stdout, proc.stderr


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

async def _run_loop(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    scenario_name, agent_name = _split_instance(args.instance)
    manifest = _resolve_manifest(Path(args.scenario_dir), scenario_name)
    scenario = parse_scenario(manifest)

    if agent_name not in scenario.agents:
        raise SystemExit(
            f"watchdog: agent {agent_name!r} not in scenario {scenario_name!r}"
        )
    spec: AgentSpec = scenario.agents[agent_name]

    mission_text = spec.mission_file.read_text(encoding="utf-8")

    # Bring up our own OpenClawAgent — read-only collector for snapshot calls.
    # Same seed file as the MCP service, but we bind a *different* IPv8 port
    # (off by 1000) so the two processes don't fight for the UDP socket.
    seed = KeyfileSeedSource(os.environ["SEED_FILE"]).load()
    identity = AgentIdentity.from_seed(seed, network=os.environ.get("NETWORK", "TESTNET"))

    snapshot_port = spec.ipv8_port + 1000
    save_dir = Path(os.environ.get("HOME", "/var/lib/delftclaw")) / "torrents"
    compiler_llm = OpenAICompatibleClient(
        base_url=os.environ.get("LLM_BASE_URL", "http://127.0.0.1:11600/v1"),
        model_id=os.environ.get("LLM_MODEL", "claude-haiku-4-5-20251001"),
        api_key=os.environ.get("LLM_API_KEY", ""),
    )
    agent = OpenClawAgent(
        identity=identity,
        llm=compiler_llm,
        config=AgentConfig(
            port=snapshot_port,
            address="127.0.0.1",
            btc_network=os.environ.get("BTC_NETWORK", "testnet"),
            save_dir=save_dir,
            initial_balance_sats=int(os.environ.get("INITIAL_BALANCE_SATS", "0")),
            community_log_path=Path(os.environ["COMMUNITY_LOG_PATH"])
            if os.environ.get("COMMUNITY_LOG_PATH") else None,
            peer_log_dir=Path(os.environ["PEER_LOG_DIR"])
            if os.environ.get("PEER_LOG_DIR") else None,
            peer_log_urls=tuple(os.environ.get("PEER_LOG_URLS", "").split()),
        ),
        bt_service=build_default_service(save_dir=save_dir),
    )
    await agent.start()

    # The watchdog uses a separate in-process OpenClawAgent for read-only
    # snapshots. Mirror the bootstrapped MCP agent enough that turn-1 state
    # describes the real service OpenClaw is about to operate through.
    publish_overlay = os.environ.get("PUBLISH_OVERLAY")
    overlay_paths = [str(path) for path in spec.publish_overlays]
    # The sentinel filter mirrors agent/cli._discover_stub_sources — without it
    # the literal string ``"none"`` (scenario_boot's no-publish placeholder)
    # was appended verbatim and _publish_overlays then tried to open it as a
    # file, logging ``failed to mirror published overlays in snapshot agent:
    # 'none'`` every boot. Routed through ``is_publish_overlay_sentinel`` so
    # the two call sites cannot drift again.
    if not is_publish_overlay_sentinel(publish_overlay) and publish_overlay not in overlay_paths:
        overlay_paths.append(publish_overlay)
    if overlay_paths:
        try:
            _publish_overlays(agent, overlay_paths)
        except Exception as exc:
            _log.warning("failed to mirror published overlays in snapshot agent: %s", exc)
    try:
        _apply_seed_content(agent, os.environ.get("SEED_CONTENT_FILE"))
    except Exception as exc:
        _log.warning("failed to mirror seed content in snapshot agent: %s", exc)

    # Load the network manifest scenario_boot wrote to disk so this
    # snapshot agent reports state.network alongside the MCP-process
    # agent that was injected over the wire at boot. Missing/unreadable
    # MANIFEST_FILE is non-fatal — state.network stays null and the LLM
    # has to discover the network via OVERLAY_OFFER (Agora-style fallback).
    manifest_file = os.environ.get("MANIFEST_FILE")
    if manifest_file:
        try:
            manifest_text = Path(manifest_file).read_text(encoding="utf-8")
            agent.load_manifest(manifest_text)
            _log.info("loaded manifest from %s (network=%s)",
                      manifest_file, agent.network_manifest.identity.get("name"))
        except FileNotFoundError:
            _log.warning("MANIFEST_FILE=%s does not exist; state.network will be null",
                         manifest_file)
        except Exception as exc:
            _log.warning("failed to load MANIFEST_FILE=%s: %s; state.network will be null",
                         manifest_file, exc)
        else:
            # Wire-fetch any default_overlays we don't already hold from
            # PUBLISH_OVERLAY. scenarios that flip wire_distribute_overlays
            # on (file_share) rely on this path to actually exercise the
            # OVERLAY_REQUEST -> OVERLAY_DELIVERY round-trip on the
            # bootstrap community. Per-overlay errors are logged but
            # non-fatal — the watchdog can still drive turns; the snapshot
            # will simply omit the missing overlays.
            try:
                loaded, errors = await agent.ensure_default_overlays_loaded()
                if loaded:
                    _log.info("wire-loaded %d default overlay(s): %s",
                              len(loaded), loaded)
                for entry in errors:
                    _log.warning("default overlay fetch failed: %s", entry)
            except Exception as exc:
                _log.warning("ensure_default_overlays_loaded raised: %s", exc)

    try:
        return await _drive(
            agent=agent,
            spec=spec,
            scenario=scenario,
            instance=args.instance,
            mission_text=mission_text,
        )
    finally:
        await agent.stop()


async def _wait_for_next_turn(
    *,
    tick_deadline: float,
    turn_end: float,
    min_floor_s: float,
    baseline_mtime: float,
    self_dir: "Path | None" = None,
    poll_s: float = WAKE_POLL_S,
) -> str:
    """Sleep until the next turn should fire, watching for a peer wake signal.

    Exits on whichever happens first AFTER the same-agent floor has elapsed:
      * ``mtime`` of THIS agent's ``.wake_signal`` exceeds ``baseline_mtime``
        → new state arrived since the previous turn started; return ``"signal"``.
      * ``tick_deadline`` is reached → normal periodic tick; return ``"tick"``.

    ``baseline_mtime`` is the mtime captured by the CALLER **before** the
    turn it just finished ran. Caller-supplied because a turn that signals
    itself (e.g. ``content_search_and_fetch`` touches the agent's own dir to
    advance fetch→author) must still wake this agent — capturing the
    baseline inside this helper would include the self-touch and the wake
    would never fire. See _drive() for the caller-side baseline capture.

    Before the floor elapses we keep sleeping even if the signal has fired,
    to prevent runaway LLM churn. The floor is also the minimum total delay
    between consecutive turns regardless of how short the prior turn was.

    Returns the wake reason for journal-grep correlation. Pure async — no
    blocking calls; safe inside the watchdog event loop.
    """
    if self_dir is None:
        self_dir = self_state_dir()
    while True:
        now = time.monotonic()
        if now >= tick_deadline:
            return "tick"
        floor_elapsed = (now - turn_end) >= min_floor_s
        if floor_elapsed and self_dir is not None:
            if read_signal_mtime(self_dir) > baseline_mtime:
                _log.info("watchdog: early wake reason=signal")
                return "signal"
        # Wake at whichever comes first: the next poll tick or the deadline.
        # ``min(...)`` keeps us from oversleeping past the cap on the final
        # iteration when ``tick_deadline - now`` is fractional-small.
        await asyncio.sleep(min(poll_s, max(0.0, tick_deadline - now)))


async def _drive(
    *,
    agent: OpenClawAgent,
    spec: AgentSpec,
    scenario,
    instance: str,
    mission_text: str,
) -> int:
    log_dir = Path(os.environ.get("LOG_DIR", str(scenario.log_dir)))
    sink = JsonlSink(log_dir / f"{spec.name}.jsonl")
    predicate = stop_predicates.resolve(spec.stop_predicate)
    history = TurnHistory(max_tail=3)

    baseline_snapshot = collect_state(agent)
    stop_predicates.set_baseline(str(agent.identity.agent_id), baseline_snapshot)
    sink.append({
        "event": "scenario_boot",
        "instance": instance,
        "agent_id": str(agent.identity.agent_id),
        "stop_predicate": spec.stop_predicate,
        "ts": time.time(),
    })

    start = time.monotonic()
    consecutive_llm_errors = 0
    turn_n = 0
    # Wake-signal baseline: the mtime of THIS agent's ``.wake_signal`` as of
    # before the current turn started. Captured here once, then refreshed at
    # the top of every turn iteration. Using a pre-turn snapshot means a tool
    # that signals this agent's own state (e.g. content_search_and_fetch
    # touches the actor's own state dir to advance fetch->author) WILL wake
    # the next sleep, because the post-turn mtime exceeds the pre-turn one.
    _self_dir = self_state_dir()

    while True:
        turn_n += 1
        elapsed = time.monotonic() - start

        # Capture the wake-signal baseline BEFORE the turn runs. Any signal
        # touched during the turn — by this agent's own tools (self-wake) or
        # by a peer (cross-agent wake) — will exceed this baseline in the
        # subsequent sleep and trigger an early wake.
        _turn_start_mtime = (
            read_signal_mtime(_self_dir) if _self_dir is not None else 0.0
        )

        snapshot = collect_state(agent)
        stop_value = predicate(snapshot)
        if stop_value:
            sink.append({
                "event": "stop", "reason": "stop_predicate_satisfied",
                "turn_n": turn_n, "elapsed_s": elapsed,
                "stop_predicate": spec.stop_predicate, "snapshot": snapshot,
            })
            _log.info("stop_predicate_satisfied turn=%d", turn_n)
            return EXIT_OK

        if turn_cap_reached(turn_n, scenario.watchdog.max_total_turns):
            sink.append({
                "event": "stop", "reason": "max_total_turns",
                "turn_n": turn_n, "elapsed_s": elapsed, "snapshot": snapshot,
            })
            _log.warning("max_total_turns hit (%d)", turn_n)
            return EXIT_TURNS_EXHAUSTED

        if wall_clock_exceeded(elapsed, scenario.watchdog.max_wall_clock_s):
            sink.append({
                "event": "stop", "reason": "max_wall_clock_s",
                "turn_n": turn_n, "elapsed_s": elapsed, "snapshot": snapshot,
            })
            _log.warning("max_wall_clock_s hit (elapsed=%.1f)", elapsed)
            return EXIT_WALL_CLOCK

        prompt = build_turn_prompt(mission_text, snapshot, history)
        ok, stdout, stderr = await asyncio.to_thread(
            _invoke_openclaw_agent,
            instance=instance,
            prompt=prompt,
            timeout_s=scenario.watchdog.interval_s,
        )

        record = {
            "event": "turn",
            "turn_n": turn_n,
            "ts": time.time(),
            "elapsed_s": elapsed,
            "snapshot": snapshot,
            "stop_predicate_value": stop_value,
            "prompt": prompt,
            "openclaw_ok": ok,
            "openclaw_stdout": stdout,
            "openclaw_stderr": stderr,
        }
        sink.append(record)

        if not ok:
            consecutive_llm_errors += 1
            _log.error("openclaw agent failed (consecutive=%d): %s",
                       consecutive_llm_errors, stderr[:200])
            history.append(TurnRecord(
                turn_n=turn_n,
                prompt=prompt,
                response_text=(
                    "OpenClaw subprocess failed before completing a bounded "
                    f"turn. stderr: {stderr[:600]}"
                ),
                stop_predicate_value=stop_value,
            ))
            if consecutive_llm_errors >= MAX_CONSECUTIVE_LLM_ERRORS:
                sink.append({
                    "event": "stop", "reason": "llm_errors",
                    "turn_n": turn_n, "elapsed_s": elapsed,
                    "consecutive_llm_errors": consecutive_llm_errors,
                })
                return EXIT_LLM_ERRORS
        else:
            consecutive_llm_errors = 0
            history.append(TurnRecord(
                turn_n=turn_n,
                prompt=prompt,
                response_text=stdout,
                stop_predicate_value=stop_value,
            ))

        # Sleep until either the tick window expires OR a peer agent signals
        # there's new state to react to (e.g. an overlay was just published).
        # The MIN_FLOOR_S delay prevents an LLM hot-loop; the wake polls
        # this agent's own .wake_signal mtime — touched by ``signal_peers``
        # from any peer's MCP-side tool. See agent/wake_signal.py.
        turn_end = time.monotonic()
        tick_deadline = start + (turn_n * scenario.watchdog.interval_s)
        await _wait_for_next_turn(
            tick_deadline=tick_deadline,
            turn_end=turn_end,
            min_floor_s=MIN_FLOOR_S,
            baseline_mtime=_turn_start_mtime,
            self_dir=_self_dir,
        )


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m deploy.watchdog")
    parser.add_argument("--instance", required=True,
                        help="systemd instance id, e.g. payment-bob")
    parser.add_argument("--scenario-dir", required=True,
                        help="dir containing scenario.yaml (and persona/goal files)")
    args = parser.parse_args()
    return asyncio.run(_run_loop(args))


if __name__ == "__main__":
    raise SystemExit(main())
