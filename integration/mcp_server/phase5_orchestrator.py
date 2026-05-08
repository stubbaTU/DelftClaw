"""Phase-5 orchestrator: boots two MCP servers, creates the room, hands off to autonomous OpenClaw agents.

Difference vs. phase4_alice_host:
- No scripted reply loop on either side. Both agents are LLM-driven.
- The orchestrator creates Alice's stake-gated room programmatically (so the
  room_id is deterministic and printable) and pins it into both autonomous
  prompts. After that, the orchestrator just keeps the MCP servers alive.

Workflow:

1. ``python -m integration.mcp_server.phase5_orchestrator`` (this file)
2. The orchestrator prints two system prompts — one for Alice, one for Bob.
3. You launch two OpenClaw chat sessions (terminals 2 and 3) and paste each
   system prompt into the matching session. Each LLM then executes its goal
   autonomously without further user input.
4. Watch ``logs/mcp_alice_phase5.stdout.log`` and ``logs/mcp_bob_phase5.stdout.log``
   to see the flow complete.

This is the M3 deliverable: two LLM-driven OpenClaw agents complete the M2
six-step flow with no human prompting beyond a single system message each.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from fastmcp import Client


REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON = REPO_ROOT / "venv" / "bin" / "python"

ALICE_MCP_URL = "http://127.0.0.1:8081/mcp"
BOB_MCP_URL = "http://127.0.0.1:8082/mcp"


# --- subprocess helpers (mirrors phase4) -------------------------------------


def _start_server(config_path: Path, log_path: Path) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log_path, "w", encoding="utf-8")
    return subprocess.Popen(
        [str(PYTHON), "-m", "integration.mcp_server", str(config_path)],
        cwd=str(REPO_ROOT),
        stdout=fh,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def _wait_for_port(host: str, port: int, timeout: float = 15.0) -> bool:
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _stop_server(proc: subprocess.Popen, label: str) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        print(f"[{label}] SIGINT timed out; SIGKILL", file=sys.stderr)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=3)


def _run_setup() -> str:
    proc = subprocess.run(
        [str(PYTHON), "-m", "integration.mcp_server.setup_demo"],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise RuntimeError(f"setup_demo failed with exit {proc.returncode}")
    sys.stderr.write(proc.stderr)
    issuer_pubkey_hex = proc.stdout.strip().splitlines()[-1].strip()
    if len(issuer_pubkey_hex) != 64:
        raise RuntimeError(
            f"unexpected issuer_pubkey_hex from setup_demo: {issuer_pubkey_hex!r}"
        )
    return issuer_pubkey_hex


# --- room creation -----------------------------------------------------------


async def _create_room(issuer_pubkey_hex: str) -> tuple[str, str]:
    async with Client(ALICE_MCP_URL) as alice:
        wa = (await alice.call_tool("delftclaw_whoami", {})).structured_content or {}
        if wa.get("error"):
            raise RuntimeError(f"alice whoami failed: {wa['error']}")
        alice_agent_id = wa["agent_id"]

        room_resp = (await alice.call_tool(
            "delftclaw_create_room",
            {"pinned_issuer_pubkey_hex": issuer_pubkey_hex, "min_stake_sats": 1000},
        )).structured_content or {}
        if room_resp.get("error"):
            raise RuntimeError(f"alice create_room failed: {room_resp['error']}")
        return room_resp["room_id_hex"], alice_agent_id


# --- prompt templates --------------------------------------------------------


def _alice_prompt(room_id_hex: str) -> str:
    return f"""You are 'alice', an autonomous agent hosting a stake-gated chat room.

You have access to tools prefixed `delftclaw-alice__`. Use them by emitting tool calls — never print JSON descriptions of tool calls, never narrate your plan. Read each tool result before deciding the next call. Stop when the goal below is satisfied.

Goal: receive one inbound message from 'bob' and reply once.

The room_id is: {room_id_hex}

Steps to execute autonomously:

1. Call delftclaw_recv_message with timeout_ms=3000 in a loop. Keep calling until the result has a non-null `message` field. Each empty result means no message yet — call again.

2. Once you have a message, call delftclaw_send_message with:
     room_id_hex="{room_id_hex}"
     text="hello back, bob"
     target_alias="bob"

3. Stop. Output a single short sentence confirming the reply was sent.

Do not call any other tools. Do not transfer sats. Do not loop forever — stop after step 3.
"""


def _bob_prompt(room_id_hex: str) -> str:
    return f"""You are 'bob', an autonomous agent joining a stake-gated chat room.

You have access to tools prefixed `delftclaw-bob__`. Use them by emitting tool calls — never print JSON descriptions of tool calls, never narrate your plan. Read each tool result before deciding the next call. Stop when the goal below is satisfied.

Goal: lock stake, join alice's room, exchange a greeting, transfer 200 sats, report your balance.

The room_id is: {room_id_hex}

Steps to execute autonomously, in order:

1. Call delftclaw_lock_for_admission with:
     room_id_hex="{room_id_hex}"
     amount=1000
     host_alias="alice"
   The result includes a `stake_proof` object — pass it unchanged into step 2.

2. Call delftclaw_join_room with:
     room_id_hex="{room_id_hex}"
     vc_id="dev-vc"
     host_alias="alice"
     stake_proof=<the exact stake_proof object from step 1>
   Verify the result has ok=true. If not, stop and report the reason.

3. Call delftclaw_send_message with:
     room_id_hex="{room_id_hex}"
     text="hello from bob"
     target_alias="alice"

4. Call delftclaw_recv_message with timeout_ms=3000 in a loop until the result has a non-null `message` field. That is alice's reply.

5. Call delftclaw_transfer with:
     recipient_alias="alice"
     amount=200

6. Call delftclaw_wallet_balance and output one short sentence with the `balance` and `locked` fields.

7. Stop. Do not loop or call further tools.
"""


# --- handoff banner ----------------------------------------------------------


_BANNER = """
╔════════════════════════════════════════════════════════════════════╗
║              M3 PHASE-5 AUTONOMOUS AGENT DEMO READY                ║
╠════════════════════════════════════════════════════════════════════╣
║  Alice MCP  → http://127.0.0.1:8081/mcp   IPv8 :9091               ║
║  Bob   MCP  → http://127.0.0.1:8082/mcp   IPv8 :9092               ║
║                                                                    ║
║  Both MCP servers must be registered in OpenClaw config (see       ║
║  integration/openclaw_setup/PHASE5.md).                            ║
╚════════════════════════════════════════════════════════════════════╝
"""


def _print_handoff(room_id_hex: str, issuer_pubkey_hex: str, alice_agent_id: str) -> None:
    alice_prompt = _alice_prompt(room_id_hex)
    bob_prompt = _bob_prompt(room_id_hex)

    print(_BANNER)
    print(f"  Room id:           {room_id_hex}")
    print(f"  Issuer pubkey hex: {issuer_pubkey_hex}")
    print(f"  Alice agent_id:    {alice_agent_id}")
    print()
    print("══════════════════ ALICE SYSTEM PROMPT ══════════════════")
    print()
    print(alice_prompt)
    print("══════════════════ BOB   SYSTEM PROMPT ══════════════════")
    print()
    print(bob_prompt)
    print("═════════════════════════════════════════════════════════")
    print()
    print("Now:")
    print("  Terminal 2:  open `openclaw chat` and paste the ALICE prompt above.")
    print("  Terminal 3:  open `openclaw chat` and paste the BOB   prompt above.")
    print()
    print("Each LLM will execute its goal autonomously. Watch:")
    print(f"  tail -f {REPO_ROOT}/logs/mcp_alice_phase5.stdout.log")
    print(f"  tail -f {REPO_ROOT}/logs/mcp_bob_phase5.stdout.log")
    print()
    print("Press Ctrl-C here to shut down both MCP servers when done.")
    print()
    sys.stdout.flush()

    # Persist prompts to disk for convenience (re-paste, scripted launch, etc.)
    state_dir = REPO_ROOT / "integration" / "configs"
    (state_dir / "phase5_room.txt").write_text(room_id_hex + "\n", encoding="utf-8")
    (state_dir / "phase5_alice_prompt.txt").write_text(alice_prompt, encoding="utf-8")
    (state_dir / "phase5_bob_prompt.txt").write_text(bob_prompt, encoding="utf-8")
    print(f"  prompts saved to {state_dir}/phase5_*_prompt.txt", file=sys.stderr)


# --- main --------------------------------------------------------------------


async def main() -> int:
    print("== setup_demo ==", file=sys.stderr)
    issuer_pubkey_hex = _run_setup()
    print(f"   issuer_pubkey_hex={issuer_pubkey_hex}", file=sys.stderr)

    print("== boot servers ==", file=sys.stderr)
    alice_log = REPO_ROOT / "logs" / "mcp_alice_phase5.stdout.log"
    bob_log = REPO_ROOT / "logs" / "mcp_bob_phase5.stdout.log"
    alice_proc = _start_server(REPO_ROOT / "integration" / "configs" / "alice.yaml", alice_log)
    bob_proc = _start_server(REPO_ROOT / "integration" / "configs" / "bob.yaml", bob_log)

    try:
        if not _wait_for_port("127.0.0.1", 8081, timeout=15.0):
            print("[fatal] alice mcp didn't open port 8081", file=sys.stderr)
            print(alice_log.read_text()[-2000:], file=sys.stderr)
            return 1
        if not _wait_for_port("127.0.0.1", 8082, timeout=15.0):
            print("[fatal] bob mcp didn't open port 8082", file=sys.stderr)
            print(bob_log.read_text()[-2000:], file=sys.stderr)
            return 1
        print("== both servers up ==", file=sys.stderr)

        room_id_hex, alice_agent_id = await _create_room(issuer_pubkey_hex)
        print(f"== room created: {room_id_hex} ==", file=sys.stderr)

        _print_handoff(room_id_hex, issuer_pubkey_hex, alice_agent_id)

        # Hold the servers alive until Ctrl-C.
        while True:
            await asyncio.sleep(60)
            print("[orchestrator] heartbeat", flush=True)
    except KeyboardInterrupt:
        print("\n[orchestrator] Ctrl-C; shutting down", file=sys.stderr)
    finally:
        print("== shutdown ==", file=sys.stderr)
        _stop_server(alice_proc, "alice")
        _stop_server(bob_proc, "bob")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
