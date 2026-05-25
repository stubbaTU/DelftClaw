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
import copy
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from deploy import stop_predicates
from deploy.mcp_snapshot import collect_state_via_mcp, load_manifest_from_file
from deploy.openclaw_output import OpenClawJsonSummary, parse_openclaw_json_stdout
from deploy.scenario import AgentSpec, parse_scenario
from deploy.turn_lock import acquire_llm_turn_lock
from deploy.turn_builder import (
    TurnHistory,
    TurnRecord,
    build_turn_prompt,
    turn_cap_reached,
    wall_clock_exceeded,
)
from identity.agent_identity import AgentIdentity
from identity.seed import KeyfileSeedSource


_log = logging.getLogger("watchdog")

DEFAULT_OPENCLAW_AGENT_ID = "main"

EXIT_OK = 0
EXIT_TURNS_EXHAUSTED = 1
EXIT_WALL_CLOCK = 2
EXIT_LLM_ERRORS = 3

MAX_CONSECUTIVE_LLM_ERRORS = 5


def _snapshot_for_prompt(
    snapshot: dict[str, Any],
    *,
    stop_predicate: str,
    stop_predicate_value: bool,
    scenario_name: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    """Attach authoritative stop status and any scenario next-action guidance."""
    out = copy.deepcopy(snapshot)
    out["stop_predicate"] = {
        "predicate": stop_predicate,
        "satisfied": bool(stop_predicate_value),
        "authority": "watchdog_evaluated_against_scenario_baseline",
    }
    guidance = _regtest_transfer_guidance(
        out,
        stop_predicate_value=stop_predicate_value,
        agent_name=agent_name,
    ) if scenario_name == "regtest_transfer" else None
    if guidance is not None:
        out["next_action_guidance"] = guidance
    return out


def _regtest_transfer_guidance(
    snapshot: dict[str, Any],
    *,
    stop_predicate_value: bool,
    agent_name: str | None,
) -> dict[str, Any] | None:
    """Return deterministic phase guidance for the regtest transfer scenario."""
    if agent_name == "alice":
        if stop_predicate_value:
            return {
                "phase": "complete",
                "action": "wait",
                "tool_call": None,
                "reason": "confirmed outgoing transfer predicate is already satisfied",
            }

        wallet = snapshot.get("wallet", {})
        unconfirmed_sent = _int_or_zero(wallet.get("unconfirmed_sent_sats"))
        if unconfirmed_sent >= 20_000:
            return {
                "phase": "confirm_payment",
                "action": "mine_one_block",
                "tool_call": {"name": "btc_mine_blocks", "arguments": {"num_blocks": 1}},
                "reason": "20000 sat outgoing payment exists but is not confirmed yet",
                "forbidden": ["peer_add"],
            }

        bob_wallet = _first_peer_wallet(snapshot)
        if bob_wallet:
            return {
                "phase": "send_payment",
                "action": "send_20000_sats_to_bob",
                "tool_call": {
                    "name": "btc_send",
                    "arguments": {"to_address": bob_wallet, "amount_sat": 20_000},
                },
                "reason": "bob is reachable and advertises a regtest receiving address",
                "forbidden": ["peer_add"],
            }
        return {
            "phase": "waiting_for_bob_wallet",
            "action": "wait",
            "tool_call": None,
            "reason": "bob has not yet advertised a bcrt1 regtest receiving address",
        }

    if agent_name == "bob":
        if stop_predicate_value:
            return {
                "phase": "complete",
                "action": "wait",
                "tool_call": None,
                "reason": "confirmed incoming payment predicate is already satisfied",
            }
        community = snapshot.get("community") or {}
        if community.get("my_membership_status") == "admitted":
            return {
                "phase": "awaiting_alice_payment",
                "action": "wait",
                "tool_call": None,
                "reason": "bob is already admitted; alice owns the payment and confirmation actions",
                "forbidden": ["community_join_via_peer", "community_donate_and_join", "peer_add"],
            }
        gatekeeper_mid = _first_peer_mid(snapshot)
        min_sats = _int_or_zero(
            ((snapshot.get("network") or {}).get("admission") or {}).get("min_sats")
        ) or 10_000
        return {
            "phase": "join_community",
            "action": "join_once",
            "tool_call": {
                "name": "community_join_via_peer",
                "arguments": {"gatekeeper_mid": gatekeeper_mid, "amount_sats": int(min_sats)},
            } if gatekeeper_mid else None,
            "reason": "bob is not admitted yet; submit the admission donation once",
            "forbidden": ["community_donate_and_join"],
        }

    return None


def _first_peer_wallet(snapshot: dict[str, Any]) -> str | None:
    for peer in snapshot.get("peers", []):
        if not isinstance(peer, dict):
            continue
        wallet = peer.get("wallet_address")
        if isinstance(wallet, str) and wallet.startswith("bcrt1"):
            return wallet
    return None


def _first_peer_mid(snapshot: dict[str, Any]) -> str | None:
    for peer in snapshot.get("peers", []):
        if isinstance(peer, dict) and isinstance(peer.get("mid_hex"), str):
            return peer["mid_hex"]
    return None


def _int_or_zero(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


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

def _reset_openclaw_session(openclaw_agent_id: str) -> None:
    """Wipe the per-HOME OpenClaw session dir so the next ``openclaw
    agent`` call starts a fresh conversation.

    OpenClaw maintains session state across invocations under
    ``$HOME/.openclaw/agents/<openclaw-agent-id>/sessions/``. Without resetting,
    every watchdog tick appends to the same session — within ~10 turns
    that overruns the model's context window (qwen3.6:27b is 32K) and
    every subsequent turn fails with "Context overflow: prompt too large".

    Removing the sessions directory is robust against openclaw CLI flag
    changes; openclaw recreates the dir on the next invocation.
    """
    home = os.environ.get("HOME")
    if not home:
        return
    sessions_dir = Path(home) / ".openclaw" / "agents" / openclaw_agent_id / "sessions"
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
    openclaw_agent_id: str,
    prompt: str,
    timeout_s: int,
    model: str,
) -> tuple[bool, str, str]:
    """Run ``openclaw agent --local --model <model> --agent <id> --message <prompt>``.

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
    _reset_openclaw_session(openclaw_agent_id)

    # ``--thinking off`` is required for non-reasoning Ollama models like
    # qwen2.5-coder:7b (they reject any other level). If/when this watchdog
    # drives a reasoning model, expose ``thinking`` via the env file.
    cmd = [
        "openclaw", "agent",
        "--local",
        "--model", model,
        "--agent", openclaw_agent_id,
        "--message", prompt,
        "--json",
        "--timeout", str(timeout_s),
        "--thinking", "off",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 30,
        )
    except subprocess.TimeoutExpired as exc:
        return False, "", f"openclaw timed out after {timeout_s + 30}s: {exc}"
    return proc.returncode == 0, proc.stdout, proc.stderr


def _classify_openclaw_turn(
    *,
    subprocess_ok: bool,
    stdout: str,
    stderr: str,
) -> tuple[bool, OpenClawJsonSummary, str | None]:
    """Return ``(turn_ok, parsed_stdout, failure_reason)`` for one turn."""
    summary = parse_openclaw_json_stdout(stdout)
    if not subprocess_ok:
        reason = stderr[:200] or summary.parse_error or "unknown_openclaw_error"
        return False, summary, reason
    if summary.semantic_error:
        return False, summary, summary.semantic_error
    return True, summary, None


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

    # Single-agent model. The watchdog no longer boots a private
    # OpenClawAgent for snapshot collection — every snapshot is taken
    # against the *real* MCP-process agent via its MCP server, so the
    # LLM finally sees the live IPv8 peer/manifest state rather than
    # the orphaned view that produced "0 IPv8 tools called" symptom
    # under the prior dual-runtime architecture.
    #
    # Identity is derived from the seed locally because it's static
    # data — ``agent_id`` and ``pubkey_hex`` never change tick-to-tick.
    # The manifest is parsed once from MANIFEST_FILE for the same
    # reason. Everything dynamic (peers, wallet, overlays, community
    # state, torrents) flows through MCP.
    seed = KeyfileSeedSource(os.environ["SEED_FILE"]).load()
    identity = AgentIdentity.from_seed(seed, network=os.environ.get("NETWORK", "TESTNET"))

    mcp_host = os.environ.get("MCP_HOST", "127.0.0.1")
    # MCP_HOST may be ``0.0.0.0`` (the bind address); local-only client
    # talks to ``127.0.0.1`` regardless of bind interface.
    mcp_client_host = "127.0.0.1" if mcp_host in ("0.0.0.0", "::") else mcp_host
    mcp_port = int(os.environ.get("MCP_PORT", "8765"))
    mcp_url = f"http://{mcp_client_host}:{mcp_port}/mcp"

    manifest_file_env = os.environ.get("MANIFEST_FILE")
    manifest = None
    if manifest_file_env:
        manifest = load_manifest_from_file(Path(manifest_file_env))
        if manifest is None:
            _log.warning(
                "MANIFEST_FILE=%s missing or unparseable; state.network will be null",
                manifest_file_env,
            )
        else:
            _log.info("loaded manifest from %s (network=%s)",
                      manifest_file_env, manifest.identity.get("name"))

    # The advertised IPv8 endpoint the LLM sees in state.agent.ipv8_address.
    # Loopback is correct for the same-VPS demo; cross-VPS deployments
    # already override this via scenario.yaml + scenario_boot wiring.
    ipv8_address = ("127.0.0.1", spec.ipv8_port)

    return await _drive(
        identity=identity,
        ipv8_address=ipv8_address,
        manifest=manifest,
        mcp_url=mcp_url,
        spec=spec,
        scenario=scenario,
        instance=args.instance,
        mission_text=mission_text,
    )


async def _drive(
    *,
    identity: AgentIdentity,
    ipv8_address: tuple[str, int],
    manifest,
    mcp_url: str,
    spec: AgentSpec,
    scenario,
    instance: str,
    mission_text: str,
) -> int:
    log_dir = Path(os.environ.get("LOG_DIR", str(scenario.log_dir)))
    sink = JsonlSink(log_dir / f"{spec.name}.jsonl")
    predicate = stop_predicates.resolve(spec.stop_predicate)
    history = TurnHistory(max_tail=3)

    async def _snapshot() -> dict[str, Any]:
        """Bind the static identity / ipv8 / manifest into each MCP call."""
        return await collect_state_via_mcp(
            mcp_url=mcp_url,
            identity=identity,
            ipv8_address=ipv8_address,
            manifest=manifest,
        )

    baseline_snapshot = await _snapshot()
    stop_predicates.set_baseline(str(identity.agent_id), baseline_snapshot)
    sink.append({
        "event": "scenario_boot",
        "instance": instance,
        "agent_id": str(identity.agent_id),
        "stop_predicate": spec.stop_predicate,
        "ts": time.time(),
    })

    # Stagger first turn so concurrent agents in the same scenario don't
    # all hit the LLM provider at the same instant (per-org concurrent-
    # request caps tend to reject the overflow). scenario_boot writes a
    # per-agent value into the env file; 0.0 means no delay.
    initial_delay_s = float(os.environ.get("WATCHDOG_INITIAL_DELAY_S", "0") or 0)
    if initial_delay_s > 0:
        _log.info("staggered initial delay: sleeping %.1fs before first turn", initial_delay_s)
        await asyncio.sleep(initial_delay_s)

    start = time.monotonic()
    consecutive_llm_errors = 0
    turn_n = 0

    while True:
        turn_n += 1
        elapsed = time.monotonic() - start

        try:
            snapshot = await _snapshot()
        except Exception as exc:
            # MCP transport hiccups shouldn't kill the watchdog — log,
            # short-sleep, and retry. systemd will eventually restart us
            # if the MCP server is genuinely down (consecutive_llm_errors
            # path doesn't apply because no LLM call happened).
            _log.warning("snapshot via MCP failed turn=%d: %s", turn_n, exc)
            await asyncio.sleep(min(scenario.watchdog.interval_s, 10.0))
            continue
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

        prompt_snapshot = _snapshot_for_prompt(
            snapshot,
            stop_predicate=spec.stop_predicate,
            stop_predicate_value=stop_value,
            scenario_name=scenario.name,
            agent_name=spec.name,
        )
        prompt = build_turn_prompt(mission_text, prompt_snapshot, history)
        # The provider prefix on ``--model`` must match the provider key
        # ``scenario_boot.py`` wrote into the agent's openclaw.json (and
        # the prefix it used when calling ``openclaw agents add --model
        # <prefix>/<name>``). The prefix used to be hardcoded ``ollama``
        # but is now provider-dependent: ``ollama`` for native Ollama,
        # ``compat`` for OpenAI-compatible endpoints (Anthropic / OpenAI /
        # Groq / etc. via the local llm proxy). Pull both from env.
        model_name = os.environ.get("LLM_MODEL", "qwen2.5-coder:7b")
        provider_key = os.environ.get("OPENCLAW_PROVIDER_KEY", "ollama")
        openclaw_agent_id = os.environ.get("OPENCLAW_AGENT_ID", DEFAULT_OPENCLAW_AGENT_ID)
        # Cross-agent lock — only one watchdog runs an openclaw turn at a
        # time across the whole scenario. Eliminates concurrent LLM
        # requests and the bursts that hit Anthropic / similar providers'
        # per-minute token caps.
        async with acquire_llm_turn_lock(instance=instance, log=_log):
            ok, stdout, stderr = await asyncio.to_thread(
                _invoke_openclaw_agent,
                openclaw_agent_id=openclaw_agent_id,
                prompt=prompt,
                timeout_s=scenario.watchdog.interval_s,
                model=f"{provider_key}/{model_name}",
            )

        turn_ok, summary, failure_reason = _classify_openclaw_turn(
            subprocess_ok=ok,
            stdout=stdout,
            stderr=stderr,
        )
        semantic_error = summary.semantic_error

        record = {
            "event": "turn",
            "turn_n": turn_n,
            "ts": time.time(),
            "elapsed_s": elapsed,
            "snapshot": snapshot,
            "stop_predicate_value": stop_value,
            "prompt": prompt,
            "openclaw_ok": turn_ok,
            "openclaw_subprocess_ok": ok,
            "openclaw_semantic_error": semantic_error,
            "openclaw_json_parse_error": summary.parse_error,
            "openclaw_stdout": stdout,
            "openclaw_stderr": stderr,
        }
        sink.append(record)

        if not turn_ok:
            consecutive_llm_errors += 1
            _log.error("openclaw agent failed (consecutive=%d): %s",
                       consecutive_llm_errors, failure_reason)
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
