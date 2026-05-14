"""Phase-3 two-server smoke: drive the M2 flow through two MCP servers.

Runs the entire M2 demo end-to-end without OpenClaw / LLM:

* Sets up a clean workspace via :mod:`integration.mcp_server.setup_demo`.
* Boots Alice's and Bob's MCP servers as subprocesses (8081 / 8082).
* Drives them via the FastMCP Python client to reproduce the M2 6-step flow:
  Alice creates a stake-gated room, Bob locks 1000 sats, Bob joins with the
  dev-vc + stake proof, Bob sends a message, Alice receives it, Bob
  transfers 200 sats. (Replay test deferred to Phase 4 — it requires
  re-issuing the same StakeOp bytes which the MCP layer doesn't expose.)
* Tears everything down.

Run::

    python -m integration.mcp_server.m3_phase3_driver

Exit 0 on green; non-zero on any step failing.
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


# --- subprocess helpers -------------------------------------------------------


def _start_server(config_path: Path, log_path: Path) -> subprocess.Popen:
    """Launch ``python -m integration.mcp_server <config>`` as a subprocess."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(PYTHON), "-m", "integration.mcp_server", str(config_path)],
        cwd=str(REPO_ROOT),
        stdout=fh,
        stderr=subprocess.STDOUT,
        # Detach into its own process group so we can SIGINT it cleanly.
        start_new_session=True,
    )
    return proc


def _wait_for_port(host: str, port: int, timeout: float = 15.0) -> bool:
    """Block until ``host:port`` accepts TCP connections, or timeout."""
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


# --- MCP driver helpers -------------------------------------------------------


async def _call(client: Client, name: str, args: dict | None = None) -> dict:
    res = await client.call_tool(name, args or {})
    sc = res.structured_content or {}
    return sc


# --- the M2 flow over two MCP servers -----------------------------------------


async def _run_flow(alice_url: str, bob_url: str, issuer_pubkey_hex: str) -> int:
    print(f"[driver] alice_mcp={alice_url}  bob_mcp={bob_url}")

    async with Client(alice_url) as alice, Client(bob_url) as bob:
        # Stage 0: identity sanity.
        wa = await _call(alice, "delftclaw_whoami")
        wb = await _call(bob, "delftclaw_whoami")
        print(f"[stage 0] alice agent_id = {wa['agent_id']}")
        print(f"[stage 0] bob   agent_id = {wb['agent_id']}")
        if wa.get("error") or wb.get("error"):
            print(f"[stage 0] FAIL: alice error={wa.get('error')!r} "
                  f"bob error={wb.get('error')!r}")
            return 1

        # Stage 1: Alice creates a stake-gated room.
        print("[stage 1] alice creates stake-gated room")
        room_resp = await _call(
            alice, "delftclaw_create_room",
            {"pinned_issuer_pubkey_hex": issuer_pubkey_hex, "min_stake_sats": 1000},
        )
        if room_resp.get("error"):
            print(f"[stage 1] FAIL: {room_resp['error']}")
            return 1
        room_id_hex = room_resp["room_id_hex"]
        print(f"           room_id={room_id_hex} policy={room_resp['policy_descriptor']}")

        # Stage 2: Bob locks stake under the room's purpose.
        print("[stage 2] bob locks 1000 sats for admission")
        lock_resp = await _call(
            bob, "delftclaw_lock_for_admission",
            {"room_id_hex": room_id_hex, "amount": 1000, "host_alias": "alice"},
        )
        if lock_resp.get("error"):
            print(f"[stage 2] FAIL: {lock_resp['error']}")
            return 1
        proof = lock_resp["stake_proof"]
        print(f"           purpose={proof['purpose']} min_sats={proof['min_sats']}")

        # Wait for Alice's oracle to mirror the broadcast lock.
        await asyncio.sleep(0.3)

        # Stage 3: Bob joins with VC + stake proof.
        print("[stage 3] bob joins room")
        join_resp = await _call(
            bob, "delftclaw_join_room",
            {
                "room_id_hex": room_id_hex,
                "vc_id": "dev-vc",
                "host_alias": "alice",
                "stake_proof": proof,
            },
        )
        if not join_resp.get("ok"):
            print(f"[stage 3] FAIL: ok={join_resp.get('ok')} "
                  f"reason={join_resp.get('reason')!r} error={join_resp.get('error')!r}")
            return 1
        print(f"           ok={join_resp['ok']} reason={join_resp['reason']!r}")

        # Stage 4: Bob sends a message; Alice receives.
        print("[stage 4] bob → alice: 'hello alice'")
        send_resp = await _call(
            bob, "delftclaw_send_message",
            {"room_id_hex": room_id_hex, "text": "hello alice", "target_alias": "alice"},
        )
        if send_resp.get("error"):
            print(f"[stage 4] FAIL on send: {send_resp['error']}")
            return 1
        print(f"           message_id={send_resp['message_id_hex'][:12]}…")

        # Poll Alice's inbox for up to 2 seconds.
        message = None
        for attempt in range(20):
            recv_resp = await _call(alice, "delftclaw_recv_message", {"timeout_ms": 0})
            if recv_resp.get("message"):
                message = recv_resp["message"]
                break
            await asyncio.sleep(0.1)
        if message is None:
            print("[stage 4] FAIL: alice never received the message")
            return 1
        print(f"           alice received: {message['text']!r} "
              f"from {message['sender_agent_id']}")
        if message["text"] != "hello alice":
            print(f"[stage 4] FAIL: text mismatch {message['text']!r}")
            return 1

        # Stage 5: Bob transfers 200 sats to Alice.
        print("[stage 5] bob → alice: transfer 200 sats")
        tx_resp = await _call(
            bob, "delftclaw_transfer",
            {"recipient_alias": "alice", "amount": 200},
        )
        if not tx_resp.get("ok"):
            print(f"[stage 5] FAIL on transfer: {tx_resp.get('error')!r}")
            return 1

        # Wait for Alice's oracle to mirror the broadcast transfer.
        await asyncio.sleep(0.3)

        # Stage 6: balance assertions.
        print("[stage 6] verify balances")
        bob_wb = await _call(bob, "delftclaw_wallet_balance")
        alice_wb = await _call(alice, "delftclaw_wallet_balance")
        print(f"           bob   balance={bob_wb['balance']}  locked={bob_wb['locked']}")
        print(f"           alice balance={alice_wb['balance']} locked={alice_wb['locked']}")

        # Bob's local view: started with 5000, locked 1000, transferred 200 → 3800.
        if bob_wb["balance"] != 3800:
            print(f"[stage 6] FAIL: bob balance expected 3800, got {bob_wb['balance']}")
            return 1
        # Bob's lock under the room purpose remains 1000.
        purpose = f"admission:room={room_id_hex}"
        if bob_wb["locked"].get(purpose, 0) != 1000:
            print(f"[stage 6] FAIL: bob locked under {purpose} expected 1000, "
                  f"got {bob_wb['locked'].get(purpose, 0)}")
            return 1

    print("\nM3 PHASE-3 SMOKE OK")
    return 0


# --- entrypoint ---------------------------------------------------------------


def _run_setup() -> str:
    """Run setup_demo as a subprocess; return the issuer pubkey hex."""
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


async def main() -> int:
    print("== setup_demo ==", file=sys.stderr)
    issuer_pubkey_hex = _run_setup()
    print(f"   issuer_pubkey_hex={issuer_pubkey_hex}", file=sys.stderr)

    print("== boot servers ==", file=sys.stderr)
    alice_log = REPO_ROOT / "logs" / "mcp_alice_phase3.stdout.log"
    bob_log = REPO_ROOT / "logs" / "mcp_bob_phase3.stdout.log"
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

        return await _run_flow(
            alice_url="http://127.0.0.1:8081/mcp",
            bob_url="http://127.0.0.1:8082/mcp",
            issuer_pubkey_hex=issuer_pubkey_hex,
        )
    finally:
        print("== shutdown ==", file=sys.stderr)
        _stop_server(alice_proc, "alice")
        _stop_server(bob_proc, "bob")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
