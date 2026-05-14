"""Phase-4 host driver: Alice plays host, you drive Bob via OpenClaw chat.

What this script does
---------------------
1. Calls :mod:`integration.mcp_server.setup_demo` to mint a fresh issuer
   keypair, derive Alice's and Bob's identities from their seed files,
   write the demo ``peers.yaml``, and issue Bob's ``dev-vc``.
2. Boots Alice's MCP server (subprocess, port 8081 / IPv8 9091).
3. Boots Bob's MCP server (subprocess, port 8082 / IPv8 9092). This is
   the server the OpenClaw chat agent will connect to.
4. Connects to Alice's MCP as a Python client and:
   - calls ``delftclaw_create_room`` with a 1000-sat stake gate,
   - prints the **room id** and the **issuer pubkey hex** to your terminal,
   - waits for any inbound message in Alice's inbox,
   - sends a single reply ``"hello back, bob"`` once a message arrives,
   - holds the host alive until you Ctrl-C.

What you do
-----------
With this script running, open OpenClaw in a separate terminal (the chat
session pointing at Bob's MCP server, configured per the Phase-4 README)
and instruct the LLM to lock stake, join Alice's room, send a greeting,
read Alice's reply, and transfer 200 sats. The script captures
everything Alice does into ``logs/mcp_alice_phase4.stdout.log`` so you
can grep for the round-trip after.

This is intentionally a one-shot host. It does not retry, persist, or
multi-turn — Phase 4 is verifying the LLM correctly sequences the tool
calls *once*. Phase 5 will run two real LLMs.

Run::

    python -m integration.mcp_server.phase4_alice_host
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


# --- subprocess helpers (same shape as phase 3) -------------------------------


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


# --- setup_demo as subprocess (returns issuer pubkey hex) ---------------------


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


# --- driver helpers -----------------------------------------------------------


async def _call(client: Client, name: str, args: dict | None = None) -> dict:
    res = await client.call_tool(name, args or {})
    return res.structured_content or {}


_BANNER = """
╔════════════════════════════════════════════════════════════════════╗
║                  M3 PHASE-4 OPENCLAW DEMO READY                    ║
╠════════════════════════════════════════════════════════════════════╣
║  Alice (host)   → http://127.0.0.1:8081/mcp   IPv8 :9091           ║
║  Bob   (joiner) → http://127.0.0.1:8082/mcp   IPv8 :9092           ║
║                                                                    ║
║  Bob's MCP server is what OpenClaw must talk to.                   ║
║  See bench/README.md and integration/openclaw_setup/PHASE4.md      ║
║  for OpenClaw config steps.                                        ║
╚════════════════════════════════════════════════════════════════════╝
"""


def _print_handoff(room_id_hex: str, issuer_pubkey_hex: str, alice_agent_id: str) -> None:
    print(_BANNER)
    print("Now switch to your OpenClaw chat session and tell the agent:")
    print()
    print("─────────────────────────── PROMPT ───────────────────────────")
    print("You are 'bob'. You have delftclaw_* tools available. Execute "
          "the calls below using the actual tool-call mechanism. Do NOT "
          "print JSON. Do NOT narrate your plan. After each call, read "
          "the result, then make the next call.")
    print()
    print(f"Room id: {room_id_hex}")
    print()
    print("CALL 1: delftclaw_lock_for_admission(")
    print(f"          room_id_hex=\"{room_id_hex}\",")
    print(f"          amount=1000,")
    print(f"          host_alias=\"alice\")")
    print("        Keep the returned `stake_proof` object.")
    print()
    print("CALL 2: delftclaw_join_room(")
    print(f"          room_id_hex=\"{room_id_hex}\",")
    print(f"          vc_id=\"dev-vc\",")
    print(f"          host_alias=\"alice\",")
    print(f"          stake_proof=<the exact stake_proof object from CALL 1>)")
    print("        Verify ok=True before continuing.")
    print()
    print("CALL 3: delftclaw_send_message(")
    print(f"          room_id_hex=\"{room_id_hex}\",")
    print(f"          text=\"hello from bob\",")
    print(f"          target_alias=\"alice\")")
    print()
    print("CALL 4: delftclaw_recv_message(timeout_ms=3000) repeatedly "
          "until the `message` field is non-null. Quote the text.")
    print()
    print("CALL 5: delftclaw_transfer(recipient_alias=\"alice\", amount=200)")
    print()
    print("CALL 6: delftclaw_wallet_balance() — report `balance` and "
          "`locked` in one short sentence.")
    print()
    print("Begin with CALL 1 now. Do not preview the plan.")
    print("──────────────────────────────────────────────────────────────")
    print()
    print(f"  Room id:           {room_id_hex}")
    print(f"  Issuer pubkey hex: {issuer_pubkey_hex}")
    print(f"  Alice agent_id:    {alice_agent_id}")
    print()
    print("Alice is waiting for an inbound message and will reply once.")
    print("Press Ctrl-C here to shut down both servers.")
    print()
    sys.stdout.flush()


async def _alice_host_loop(issuer_pubkey_hex: str) -> None:
    """Connect to Alice's MCP server, prepare the room, await one message."""
    async with Client(ALICE_MCP_URL) as alice:
        # 0. Confirm identity.
        wa = await _call(alice, "delftclaw_whoami")
        if wa.get("error"):
            raise RuntimeError(f"alice whoami failed: {wa['error']}")
        alice_agent_id = wa["agent_id"]

        # 1. Create the stake-gated room.
        room_resp = await _call(
            alice, "delftclaw_create_room",
            {"pinned_issuer_pubkey_hex": issuer_pubkey_hex, "min_stake_sats": 1000},
        )
        if room_resp.get("error"):
            raise RuntimeError(f"alice create_room failed: {room_resp['error']}")
        room_id_hex = room_resp["room_id_hex"]

        # Hand off to the human / LLM.
        _print_handoff(room_id_hex, issuer_pubkey_hex, alice_agent_id)

        # 2. Poll the inbox until something arrives or we get Ctrl-C'd.
        print("[alice] waiting for inbound message…", flush=True)
        message = None
        while message is None:
            recv = await _call(alice, "delftclaw_recv_message", {"timeout_ms": 0})
            if recv.get("message"):
                message = recv["message"]
                break
            await asyncio.sleep(0.5)

        print(f"[alice] received: {message['text']!r} from "
              f"{message['sender_agent_id']}", flush=True)

        # 3. Reply once.
        reply = await _call(
            alice, "delftclaw_send_message",
            {
                "room_id_hex": room_id_hex,
                "text": "hello back, bob",
                "target_alias": "bob",
            },
        )
        if reply.get("error"):
            print(f"[alice] reply send failed: {reply['error']}", flush=True)
        else:
            print(f"[alice] replied: 'hello back, bob' "
                  f"(message_id={reply['message_id_hex'][:12]}…)", flush=True)

        # 4. Hold the host alive for further LLM interaction (transfer step).
        print("[alice] holding open; press Ctrl-C to shut down", flush=True)
        while True:
            await asyncio.sleep(60)
            wb = await _call(alice, "delftclaw_wallet_balance")
            print(f"[alice] heartbeat: balance={wb['balance']} "
                  f"locked={wb['locked']}", flush=True)


async def main() -> int:
    print("== setup_demo ==", file=sys.stderr)
    issuer_pubkey_hex = _run_setup()
    print(f"   issuer_pubkey_hex={issuer_pubkey_hex}", file=sys.stderr)

    print("== boot servers ==", file=sys.stderr)
    alice_log = REPO_ROOT / "logs" / "mcp_alice_phase4.stdout.log"
    bob_log = REPO_ROOT / "logs" / "mcp_bob_phase4.stdout.log"
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

        await _alice_host_loop(issuer_pubkey_hex)
    except KeyboardInterrupt:
        print("\n[main] Ctrl-C; shutting down", file=sys.stderr)
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
