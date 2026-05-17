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
import sys
import time
from dataclasses import asdict
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


_log = logging.getLogger("watchdog")

EXIT_OK = 0
EXIT_TURNS_EXHAUSTED = 1
EXIT_WALL_CLOCK = 2
EXIT_LLM_ERRORS = 3

MAX_CONSECUTIVE_LLM_ERRORS = 5


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
    that overruns the model's context window (qwen3.6:27b is 32K) and
    every subsequent turn fails with "Context overflow: prompt too large".

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
    model: str,
) -> tuple[bool, str, str]:
    """Run ``openclaw agent --local --model <model> --agent <instance> --message <prompt>``.

    ``--local`` skips OpenClaw's WebSocket gateway daemon (which we don't
    run on the VPS) and uses the embedded agent path instead. ``--model``
    routes inference through the Ollama provider registered in this
    agent's per-HOME openclaw.json by ``scenario_boot.py``.

    Returns ``(ok, stdout, stderr)``. ``ok`` is True iff the subprocess
    exited 0 within timeout.
    """
    # Reset the session BEFORE every call so context doesn't accumulate
    # across watchdog ticks. The agent re-reads the full state snapshot
    # each turn anyway — there's nothing in session history a fresh start
    # actually loses for our use case.
    _reset_openclaw_session(instance)

    # ``--thinking off`` is required for non-reasoning Ollama models like
    # qwen2.5-coder:7b (they reject any other level). If/when this watchdog
    # drives a reasoning model, expose ``thinking`` via the env file.
    cmd = [
        "openclaw", "agent",
        "--local",
        "--model", model,
        "--agent", instance,
        "--message", prompt,
        "--json",
        "--timeout", str(timeout_s),
        "--thinking", "off",
    ]
    # Forward the Claude-CLI MCP config so the patched openclaw provider
    # can pass --mcp-config to claude. Without this env, openclaw spawns
    # claude with no MCP wiring and Haiku has no callable tools — every
    # reply is hallucinated chat text. Scenario_boot writes the JSON to
    # $HOME/openclaw/claude-mcp-config.json at provision time.
    env = os.environ.copy()
    mcp_config = Path(env.get("HOME", "/var/lib/delftclaw")) / "openclaw" / "workspace" / "claude-mcp-config.json"
    if mcp_config.exists():
        env["CLAUDE_MCP_CONFIG"] = str(mcp_config)
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

    # Mission text now lives in the openclaw workspace as SOUL.md (written
    # by scenario_boot._provision_openclaw_workspace) and is auto-injected
    # into the system prompt on every ``openclaw agent`` call. The watchdog
    # itself no longer needs the prose, but we still touch the file here so
    # a missing/unreadable mission_file fails fast at boot rather than on
    # the first tick.
    spec.mission_file.read_text(encoding="utf-8")

    # Bring up our own OpenClawAgent — read-only collector for snapshot calls.
    # Same seed file as the MCP service, but we bind a *different* IPv8 port
    # (off by 1000) so the two processes don't fight for the UDP socket.
    seed = KeyfileSeedSource(os.environ["SEED_FILE"]).load()
    identity = AgentIdentity.from_seed(seed, network=os.environ.get("NETWORK", "TESTNET"))

    snapshot_port = spec.ipv8_port + 1000
    save_dir = Path(os.environ.get("HOME", "/var/lib/delftclaw")) / "torrents"
    compiler_llm = OpenAICompatibleClient(
        base_url=os.environ.get("QWEN_BASE_URL", "http://127.0.0.1:11434/v1"),
        model_id=os.environ.get("QWEN_MODEL", "qwen2.5-coder:7b"),
    )
    agent = OpenClawAgent(
        identity=identity,
        llm=compiler_llm,
        config=AgentConfig(
            port=snapshot_port,
            address="127.0.0.1",
            btc_network=os.environ.get("BTC_NETWORK", "testnet"),
            save_dir=save_dir,
        ),
        bt_service=build_default_service(save_dir=save_dir),
    )
    await agent.start()

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

    try:
        return await _drive(
            agent=agent,
            spec=spec,
            scenario=scenario,
            instance=args.instance,
        )
    finally:
        await agent.stop()


async def _drive(
    *,
    agent: OpenClawAgent,
    spec: AgentSpec,
    scenario,
    instance: str,
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

    while True:
        turn_n += 1
        elapsed = time.monotonic() - start

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

        prompt = build_turn_prompt(snapshot, history)
        ok, stdout, stderr = await asyncio.to_thread(
            _invoke_openclaw_agent,
            instance=instance,
            prompt=prompt,
            timeout_s=scenario.watchdog.interval_s,
            model="claude-cli/claude-haiku-4-5",
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

        # Sleep the remaining time inside this tick — never sleep negative.
        tick_remaining = scenario.watchdog.interval_s - (time.monotonic() - start - elapsed)
        if tick_remaining > 0:
            await asyncio.sleep(tick_remaining)


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m deploy.watchdog")
    parser.add_argument("--instance", required=True,
                        help="systemd instance id, e.g. seek_cc-bob")
    parser.add_argument("--scenario-dir", required=True,
                        help="dir containing scenario.yaml (and persona/goal files)")
    args = parser.parse_args()
    return asyncio.run(_run_loop(args))


if __name__ == "__main__":
    raise SystemExit(main())
