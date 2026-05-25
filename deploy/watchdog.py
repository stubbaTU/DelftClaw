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

from agent.runtime import AgentConfig, OpenClawAgent
from communication.bittorrent import build_default_service
from deploy import stop_predicates
from deploy.openclaw_output import OpenClawJsonSummary, parse_openclaw_json_stdout
from deploy.scenario import AgentSpec, parse_scenario
from deploy.security_agent_tools import add_integrated_security_tools, build_security_tools
from deploy.state_snapshot import collect_state
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
from protocol.llm import OpenAICompatibleClient
from agent.cli import _apply_seed_content, _publish_overlays
from agent.loop import OpenAICompatibleToolLLM, run_tool_loop
from agent.tools import build_tools


_log = logging.getLogger("watchdog")

DEFAULT_OPENCLAW_AGENT_ID = "main"

EXIT_OK = 0
EXIT_TURNS_EXHAUSTED = 1
EXIT_WALL_CLOCK = 2
EXIT_LLM_ERRORS = 3

MAX_CONSECUTIVE_LLM_ERRORS = 5

COMMUNITY_DEMO_TOOL_ALLOWLIST = {
    "peers_list",
    "wallet_address",
    "wallet_balance",
    "community_log_list_recent",
    "community_treasury_balance",
    "community_member_count",
    "community_donate_and_join",
    "community_join_via_peer",
    "content_search_and_fetch",
    "network_join",
    "overlay_invoke",
    "overlays_list",
    "seedbox_purchase_propose",
    "seedbox_provisioned",
    "torrent_fetch",
    "torrent_stats",
    "run_integrated_security_episode",
}

SECURE_COMMUNITY_DEMO_TOOL_DENYLIST = {
    # These are intentionally absent from the real OpenClaw-facing tool
    # surface. The integrated security episode asks for them through the
    # defended gateway so Brain may request them, but Hands must block them.
    "broadcast_payment",
    "create_fake_seedbox",
    "delete_audit_log",
    "exfiltrate_private_key",
    "exfiltrate_secret",
    "modify_iptables",
    "run_shell",
}


def _compact_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Trim prompt-only state for low request-size providers.

    Stop predicates and JSONL still receive the full snapshot; this is only
    what the LLM sees. The community demo's normal flow can reason from the
    manifest/admission, wallet, community summary, peers, and torrent status
    without embedding every overlay message schema on every turn.
    """
    agent = snapshot.get("agent") or {}
    overlays_loaded = []
    for item in snapshot.get("overlays") or []:
        messages = []
        for message in item.get("messages") or []:
            name = message.get("name")
            if name not in {"SEARCH_REQUEST", "SEARCH_RESPONSE"}:
                continue
            messages.append({
                "name": name,
                "fields": [
                    field.get("name")
                    for field in message.get("fields") or []
                    if field.get("name")
                ],
            })
        overlays_loaded.append({
            "community_id_hex": item.get("community_id_hex"),
            "name": item.get("name"),
            "messages": messages,
            "usage_hint": (
                "For content_community, a seeker sends SEARCH_REQUEST to a seedbox peer. "
                "SEARCH_RESPONSE is sent automatically by the seedbox handler; do not send "
                "SEARCH_RESPONSE manually as a seeker. After a response arrives, read "
                "response_cache and call torrent_fetch on the returned magnet."
                if item.get("name") == "content_community" else None
            ),
            "local_index": (item.get("local_index") or [])[:5],
            "response_cache": (item.get("response_cache") or [])[-5:],
        })

    return {
        "ts": snapshot.get("ts"),
        "agent": {
            "agent_id": agent.get("agent_id"),
            "wallet_address": agent.get("wallet_address"),
        },
        "network": snapshot.get("network"),
        "wallet": snapshot.get("wallet"),
        "community": snapshot.get("community"),
        "peers": snapshot.get("peers"),
        "torrents": snapshot.get("torrents"),
        "overlays_loaded": overlays_loaded,
        "security": snapshot.get("security"),
        "stop_predicate": snapshot.get("stop_predicate"),
        "next_action_guidance": snapshot.get("next_action_guidance"),
    }


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
) -> tuple[bool, str, str]:
    """Run ``openclaw agent --local --agent <id> --message <prompt>``.

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
    _reset_openclaw_session(openclaw_agent_id)

    # ``--thinking off`` is required for non-reasoning Ollama models like
    # qwen2.5-coder:7b (they reject any other level). If/when this watchdog
    # drives a reasoning model, expose ``thinking`` via the env file.
    cmd = [
        "openclaw", "agent",
        "--local",
        "--agent", openclaw_agent_id,
        "--message", prompt,
        "--json",
        "--timeout", str(timeout_s),
        "--thinking", "off",
    ]
    env = os.environ.copy()
    env.setdefault("OLLAMA_API_KEY", "ollama")
    api_key_env = env.get("OPENCLAW_API_KEY_ENV")
    if api_key_env and api_key_env in os.environ:
        env[api_key_env] = os.environ[api_key_env]
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


async def _invoke_direct_tool_loop(
    *,
    agent: OpenClawAgent,
    agent_name: str,
    prompt: str,
    timeout_s: int,
    max_iterations: int,
) -> tuple[bool, str, str]:
    """Drive DelftClaw's native tool loop directly.

    This avoids OpenClaw's large built-in tool bundle. Gemini's
    OpenAI-compatible endpoint rejects that bundle's schema before a turn can
    start, while DelftClaw's own tool surface is smaller and is all the paper
    demo needs.
    """
    api_key_env = os.environ.get("OPENCLAW_API_KEY_ENV", "GEMINI_API_KEY")
    api_key = os.environ.get(api_key_env, "")
    provider = os.environ.get("OPENCLAW_PROVIDER", "").strip().lower()
    llm = OpenAICompatibleToolLLM(
        base_url=os.environ.get("OPENCLAW_BASE_URL")
        or os.environ.get("QWEN_BASE_URL", "http://127.0.0.1:11434/v1"),
        model_id=os.environ.get("OPENCLAW_MODEL")
        or os.environ.get("QWEN_MODEL", "qwen2.5-coder:7b"),
        api_key=api_key,
        timeout_s=max(30, timeout_s - 15),
        extra_body={"reasoning": {"enabled": False}} if provider == "openrouter" else {},
    )
    tool_allowlist = os.environ.get("DIRECT_TOOL_ALLOWLIST", "community_demo").strip().lower()
    if tool_allowlist == "security_layers":
        tools = build_security_tools(agent_name)
    else:
        tools = build_tools(agent)
    if tool_allowlist == "secure_community_demo":
        tools = add_integrated_security_tools(tools, agent_name)
    if tool_allowlist == "community_demo":
        tools._tools = {  # type: ignore[attr-defined]
            name: tool
            for name, tool in tools._tools.items()  # type: ignore[attr-defined]
            if name in COMMUNITY_DEMO_TOOL_ALLOWLIST
        }
    if tool_allowlist == "secure_community_demo":
        tools._tools = {  # type: ignore[attr-defined]
            name: tool
            for name, tool in tools._tools.items()  # type: ignore[attr-defined]
            if name in COMMUNITY_DEMO_TOOL_ALLOWLIST
            and name not in SECURE_COMMUNITY_DEMO_TOOL_DENYLIST
        }
    try:
        text = await asyncio.wait_for(
            run_tool_loop(
                prompt,
                llm,
                tools,
                max_iterations=max_iterations,
            ),
            timeout=timeout_s,
        )
    except Exception as exc:
        return False, "", f"{type(exc).__name__}: {exc}"
    return True, text, ""


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
    if publish_overlay and publish_overlay not in overlay_paths:
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

        prompt_snapshot_full = _snapshot_for_prompt(
            snapshot,
            stop_predicate=spec.stop_predicate,
            stop_predicate_value=stop_value,
            scenario_name=scenario.name,
            agent_name=spec.name,
        )
        driver = os.environ.get("WATCHDOG_DRIVER", "openclaw").strip().lower()
        prompt_snapshot = (
            _compact_snapshot(prompt_snapshot_full)
            if driver == "direct"
            else prompt_snapshot_full
        )
        prompt = build_turn_prompt(mission_text, prompt_snapshot, history)
        openclaw_agent_id = os.environ.get("OPENCLAW_AGENT_ID", DEFAULT_OPENCLAW_AGENT_ID)
        if driver == "direct":
            ok, stdout, stderr = await _invoke_direct_tool_loop(
                agent=agent,
                agent_name=spec.name,
                prompt=prompt,
                timeout_s=scenario.watchdog.interval_s + 30,
                max_iterations=scenario.watchdog.max_iterations_per_turn,
            )
        else:
            # Cross-agent lock: only one watchdog runs an OpenClaw turn at a
            # time across the scenario, avoiding provider token bursts.
            async with acquire_llm_turn_lock(instance=instance, log=_log):
                ok, stdout, stderr = await asyncio.to_thread(
                    _invoke_openclaw_agent,
                    openclaw_agent_id=openclaw_agent_id,
                    prompt=prompt,
                    timeout_s=scenario.watchdog.interval_s,
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
            history.append(TurnRecord(
                turn_n=turn_n,
                prompt=prompt,
                response_text=(
                    "OpenClaw subprocess failed before completing a bounded "
                    f"turn. reason: {failure_reason or stderr[:600]}"
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
