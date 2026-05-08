"""Smoke-test client for the M3 MCP server.

Exercises all 10 ``delftclaw_*`` tools end-to-end against a running
DelftClaw MCP server (default URL ``http://127.0.0.1:8081/mcp``). Uses
FastMCP's Python ``Client`` over real streamable-HTTP — same protocol
OpenClaw uses — so a green run confirms the wire layer is healthy.

In Phase 1 the tool bodies are stubs; in Phase 2+ this same script
exercises the wired-up :class:`AgentChannel` paths.

Run:
    # Boot a server first, in another terminal:
    python -m integration.mcp_server integration/configs/alice.yaml

    # Then probe it:
    python -m integration.mcp_server.smoke_client
    # or with a custom URL:
    python -m integration.mcp_server.smoke_client http://127.0.0.1:8082/mcp
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

from fastmcp import Client


DEFAULT_URL = "http://127.0.0.1:8081/mcp"


async def _call(client: Client, name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Call a tool with top-level kwargs and return ``structured_content``."""
    result = await client.call_tool(name, args or {})
    return result.structured_content or {}


async def main(url: str = DEFAULT_URL) -> None:
    print(f"connecting: {url}")
    async with Client(url) as client:
        tools = await client.list_tools()
        names = sorted(t.name for t in tools)
        print(f"discovered {len(names)} tools: {names}")
        assert len(names) == 10, f"expected 10 tools, got {len(names)}"

        wh = await _call(client, "delftclaw_whoami")
        print(f"whoami: agent_id={wh['agent_id']} network={wh['network']}")

        peers = await _call(client, "delftclaw_list_peers")
        aliases = [p["alias"] for p in peers["peers"]]
        print(f"peers: {len(aliases)} known: {aliases}")

        room = await _call(
            client,
            "delftclaw_create_room",
            {"pinned_issuer_pubkey_hex": "ab" * 32, "min_stake_sats": 1000},
        )
        room_id_hex = room["room_id_hex"]
        print(f"create_room: room_id={room_id_hex[:12]}… policy={room['policy_descriptor']}")

        lock = await _call(
            client,
            "delftclaw_lock_for_admission",
            {"room_id_hex": room_id_hex, "amount": 1000, "host_alias": "alice"},
        )
        stake_proof = lock["stake_proof"]
        print(f"lock: purpose={stake_proof['purpose']} min_sats={stake_proof['min_sats']}")

        join = await _call(
            client,
            "delftclaw_join_room",
            {
                "room_id_hex": room_id_hex,
                "vc_id": "dev-vc",
                "host_alias": "alice",
                "stake_proof": stake_proof,
            },
        )
        print(f"join: ok={join['ok']} reason={join['reason']}")

        sent = await _call(
            client,
            "delftclaw_send_message",
            {"room_id_hex": room_id_hex, "text": "hi", "target_alias": "bob"},
        )
        print(f"send: message_id={sent['message_id_hex'][:12]}…")

        rcv = await _call(client, "delftclaw_recv_message", {"timeout_ms": 0})
        print(f"recv: message={rcv['message']}")

        tr = await _call(client, "delftclaw_transfer", {"recipient_alias": "bob", "amount": 200})
        print(f"transfer: ok={tr['ok']}")

        rooms = await _call(client, "delftclaw_list_rooms")
        print(f"list_rooms: {rooms['room_ids_hex']}")

        wb = await _call(client, "delftclaw_wallet_balance")
        print(f"wallet_balance: balance={wb['balance']} locked={wb['locked']}")

    print("\nMCP SMOKE OK")


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    asyncio.run(main(url))
