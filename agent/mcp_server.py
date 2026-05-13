"""FastMCP streamable-HTTP server wrapping the agent's tool surface.

The actual OpenClaw chat session is the reasoning LLM. This server exposes
``OpenClawAgent``'s 12 tools so OpenClaw can call them over the wire — same
deployment shape as the colleague's security gateway, but the tools are
the communication/network surface (peers, wallet, overlays, torrents)
instead of the privilege/accountability surface.

There are now **two LLMs** in the picture, and they do not overlap:

  - **OpenClaw's LLM** (whatever model OpenClaw is configured with) —
    the agent's brain. Decides *which* tool to call. Talks to this
    server over MCP.
  - **The compiler LLM** (e.g. Qwen on the supervisor's GPU host) —
    called by ``OverlayRegistry`` *only* when this node needs to
    compile a ``.md`` overlay descriptor it has never seen before.
    Configured via ``--llm-base-url`` / ``--llm-model`` on the agent
    side. Never talks to OpenClaw.

Boot via ``python -m agent ... mcp --mcp-host 0.0.0.0 --mcp-port 8765``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from agent.runtime import OpenClawAgent
from agent.tools import _resolve_peer  # type: ignore[attr-defined]
from communication.community import overlay_id
from protocol.compiler import _coerce_field_value  # type: ignore[attr-defined]


SERVER_INSTRUCTIONS = """\
DelftClaw agent tools. Use these to operate on the P2P content network:

  - peers_list / wallet_* — local-node introspection + Bitcoin ops.
  - seedbox_donate_and_join — admission flow (pay, then JOIN_REQUEST).
  - overlay_fetch_and_load — when a peer offers a protocol you don't yet
    speak, fetch the markdown descriptor over the wire and compile it
    locally. After this returns, that overlay's messages are usable via
    overlay_invoke.
  - overlay_invoke — send a message defined by a compiled overlay.
  - torrent_* — fetch/seed by magnet URI.

If you receive an unfamiliar md_hash from a peer, fetch+load the
descriptor first before trying to invoke it.
"""


def build_mcp_server(agent: OpenClawAgent, *, name: str = "delftclaw-agent") -> FastMCP:
    """Wrap an ``OpenClawAgent`` as a FastMCP server.

    Each of the 12 tools is registered as a typed async function so FastMCP
    can produce the OpenAI-style JSON schema automatically. The functions
    close over ``agent``.
    """
    mcp = FastMCP(name=name, instructions=SERVER_INSTRUCTIONS)

    # ---- Peers ---------------------------------------------------------

    async def peers_list() -> list[dict[str, Any]]:
        """List peers verified on any overlay this agent runs.

        Returns a list of {mid_hex, address} dicts.
        """
        out: list[dict[str, Any]] = []
        for p in agent.known_peers():
            addr = list(p.addresses.values())[0] if p.addresses else None
            out.append({"mid_hex": p.mid.hex(), "address": addr})
        return out

    mcp.add_tool(peers_list)

    async def peer_add(host: str, port: int, pubkey_hex: str) -> dict[str, Any]:
        """Introduce a peer to this agent's IPv8 network at runtime.

        ``host``/``port`` is the remote peer's IPv8 UDP endpoint.
        ``pubkey_hex`` is the serialised IPv8 public key (74 hex chars, the
        ``ipv8_pubkey_hex`` field of the remote agent's ``info`` output).
        The peer is added to every currently-loaded overlay's network so
        bootstrap + protocol overlays can both reach it.

        Returns ``{mid_hex, address}``.
        """
        peer = agent.add_peer(host, port, pubkey_hex)
        return {
            "mid_hex": peer.mid.hex(),
            "address": list(peer.addresses.values())[0] if peer.addresses else None,
        }

    mcp.add_tool(peer_add)

    # ---- Wallet --------------------------------------------------------

    async def wallet_address() -> str:
        """Return this agent's testnet receiving address (bech32)."""
        return agent.wallet.address()

    mcp.add_tool(wallet_address)

    async def wallet_balance() -> int:
        """Return this agent's wallet balance in satoshis (refreshes from network)."""
        return agent.wallet.balance_sats(refresh=True)

    mcp.add_tool(wallet_balance)

    async def wallet_send(to_address: str, sats: int) -> str:
        """Send satoshis to a Bitcoin address. Returns the broadcast txid (hex)."""
        return agent.wallet.send(to_address, sats)

    mcp.add_tool(wallet_send)

    # ---- Seedbox admission --------------------------------------------

    async def seedbox_donate_and_join(
        gatekeeper_mid: str,
        sats: int,
        gatekeeper_address: str,
    ) -> dict[str, Any]:
        """Donate satoshis to a gatekeeper's address, then JOIN_REQUEST them.

        Returns {txid, accepted}.
        """
        import asyncio
        peer = _resolve_peer(agent, gatekeeper_mid)
        txid = agent.wallet.send(gatekeeper_address, sats)
        future = agent.seedbox.request_join(peer, bytes.fromhex(txid))
        accepted = await asyncio.wait_for(future, timeout=60)
        return {"txid": txid, "accepted": bool(accepted)}

    mcp.add_tool(seedbox_donate_and_join)

    # ---- Overlays ------------------------------------------------------

    async def overlays_list() -> list[dict[str, Any]]:
        """List the compiled overlays this agent has loaded.

        Each entry is {community_id_hex, name, version, messages}.
        """
        out: list[dict[str, Any]] = []
        for community_id in agent.registry.list_loaded():
            compiled = agent.registry._compiled[community_id]
            out.append({
                "community_id_hex": community_id.hex(),
                "name": compiled.parsed.identity.get("name", ""),
                "version": compiled.parsed.identity.get("version", ""),
                "messages": [m.name for m in compiled.parsed.messages],
            })
        return out

    mcp.add_tool(overlays_list)

    async def overlay_fetch_and_load(peer_mid: str, md_hash_hex: str) -> dict[str, Any]:
        """Ask a peer for an overlay descriptor by md_hash, compile + register it locally.

        Returns {community_id_hex, loaded}.
        """
        import asyncio
        peer = _resolve_peer(agent, peer_mid)
        md_hash = bytes.fromhex(md_hash_hex)
        future = agent.seedbox.fetch_overlay(peer, md_hash)
        md_bytes = await asyncio.wait_for(future, timeout=10)
        instance = agent.registry.load(md_bytes.decode("utf-8"))
        return {"community_id_hex": instance.community_id.hex(), "loaded": True}

    mcp.add_tool(overlay_fetch_and_load)

    async def overlay_publish(md_text: str) -> str:
        """Publish (serve + locally load) a markdown overlay descriptor.

        Returns the 20-byte md_hash as hex.
        """
        md_hash = agent.seedbox.publish_overlay(md_text)
        agent.registry.load(md_text)
        return md_hash.hex()

    mcp.add_tool(overlay_publish)

    async def overlay_invoke(
        community_id_hex: str,
        message_name: str,
        peer_mid: str,
        fields: dict[str, Any],
    ) -> dict[str, Any]:
        """Send a message defined by a compiled overlay to a peer.

        ``fields`` maps field_name -> value (str / int / list / dict).
        """
        community_id = bytes.fromhex(community_id_hex)
        instance = agent.registry.get(community_id)
        if instance is None:
            return {"error": f"overlay_not_loaded:{community_id_hex}"}
        compiled = agent.registry._compiled[community_id]
        if message_name not in compiled.payload_classes:
            return {"error": f"unknown_message:{message_name}"}
        payload_cls = compiled.payload_classes[message_name]
        coerced = [_coerce_field_value(v) for v in fields.values()]
        peer = _resolve_peer(agent, peer_mid)
        instance.ez_send(peer, payload_cls(*coerced))
        return {"sent": True}

    mcp.add_tool(overlay_invoke)

    # ---- BitTorrent ---------------------------------------------------

    async def torrent_seed(path: str) -> str:
        """Begin seeding a local file. Returns the resulting magnet URI."""
        return agent.bittorrent.seed(Path(path))

    mcp.add_tool(torrent_seed)

    async def torrent_fetch(magnet_uri: str, timeout_s: float = 600.0) -> str:
        """Download a magnet URI to local disk; returns the saved path."""
        import asyncio
        future = agent.bittorrent.add_magnet(magnet_uri)
        path = await asyncio.wait_for(future, timeout=timeout_s)
        return str(path)

    mcp.add_tool(torrent_fetch)

    async def torrent_stats() -> list[dict[str, Any]]:
        """Snapshot of all currently-known torrents (downloads + seeds)."""
        return [
            {
                "magnet": t.magnet,
                "name": t.name,
                "progress": t.progress,
                "seeding": t.seeding,
                "save_path": str(t.save_path) if t.save_path else None,
                "peers": t.peers,
            }
            for t in agent.bittorrent.stats()
        ]

    mcp.add_tool(torrent_stats)

    return mcp


async def serve_mcp_async(
    agent: OpenClawAgent,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> None:
    """Build the MCP server and serve it over streamable-HTTP until cancelled.

    Streamable-HTTP is the transport OpenClaw uses; ``--mcp-host 0.0.0.0``
    + a firewall opening on ``port`` is what a VPS deployment looks like.
    """
    mcp = build_mcp_server(agent)
    await mcp.run_async(transport="streamable-http", host=host, port=port)
