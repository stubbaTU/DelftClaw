"""FastMCP streamable-HTTP server wrapping the agent's tool surface.

The actual OpenClaw chat session is the reasoning LLM. This server exposes
``OpenClawAgent``'s 16 tools (v5.1) so OpenClaw can call them over the wire
— same deployment shape as the colleague's security gateway, but the tools
are the communication/network surface (peers, wallet, overlays, manifests,
torrents) instead of the privilege/accountability surface.

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

import logging
import os
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from agent.runtime import OpenClawAgent
from agent.tools import (  # type: ignore[attr-defined]
    _resolve_peer,
    _wire_logger,
    build_tools,
)
from communication.community import overlay_id
from protocol.compiler import _coerce_field_value  # type: ignore[attr-defined]


_log = logging.getLogger("delftclaw.agent.mcp_server")


# Tools that scenario_boot needs to call BEFORE the LLM is involved
# (wallet_address for self-introspection, peer_add for cross-agent peer
# introductions, agent_inject_manifest for pushing the network manifest
# from the boot script into the MCP-process agent). These are always
# registered regardless of MCP_TOOL_ALLOWLIST — the allowlist is an
# LLM-facing surface filter, not a security boundary, and these tools
# are called over MCP from trusted boot scripts only.
BOOTSTRAP_TOOLS: frozenset[str] = frozenset({
    "wallet_address",
    "peer_add",
    "agent_inject_manifest",
})


SERVER_INSTRUCTIONS = """\
DelftClaw agent tools. Use these to operate on the P2P content network:

  - peers_list / wallet_* — local-node introspection + Bitcoin ops.
  - agent_inject_manifest — load a network manifest into the runtime so
    state.network is populated; pre-introduces every genesis peer.
  - network_join — one-shot admission: parse manifest (or use cached),
    fetch default overlays from a genesis peer, donate the required sats,
    send JOIN_REQUEST. The recommended entry point when state.network is
    set but you have not yet joined.
  - seedbox_donate_and_join — the manual decomposition of network_join's
    last two steps; use only if you want explicit control.
  - overlays_list — every loaded overlay's full per-message field schema
    and handler text. Read this before calling overlay_invoke.
  - overlay_describe — canonical markdown for one overlay (use when
    handler_text in overlays_list is ambiguous).
  - overlay_fetch_and_load — pull a descriptor from a peer by md_hash and
    compile + register it. After this returns, overlay_invoke works.
  - overlay_invoke — send a message defined by a compiled overlay.
  - torrent_* — fetch/seed by magnet URI.

If you receive an unfamiliar md_hash from a peer, fetch+load the
descriptor first before trying to invoke it.
"""


def build_mcp_server(agent: OpenClawAgent, *, name: str = "delftclaw-agent") -> FastMCP:
    """Wrap an ``OpenClawAgent`` as a FastMCP server.

    Each of the 16 tools (v5.1) is registered as a typed async function so
    FastMCP can produce the OpenAI-style JSON schema automatically. The
    functions close over ``agent``.
    """
    OVERLAY_DESCRIBE_MAX_BYTES = 32 * 1024
    mcp = FastMCP(name=name, instructions=SERVER_INSTRUCTIONS)

    # MCP tool allowlist. Env var ``MCP_TOOL_ALLOWLIST`` is written by
    # scenario_boot from the mission's optional ``# Tools`` section.
    #
    #   var absent (None) -> register every tool (legacy behaviour).
    #   var present, empty value -> register nothing — agent can observe
    #       but cannot act this scenario.
    #   var present, csv -> register only listed names; the OpenClaw
    #       client never sees the suppressed tools, so the upstream LLM
    #       physically cannot call them.
    #
    # We bind once at build time (the allowlist is static for the life
    # of the MCP process).
    _allowlist_raw = os.environ.get("MCP_TOOL_ALLOWLIST")
    _allowlist: set[str] | None = (
        None if _allowlist_raw is None
        else {part.strip() for part in _allowlist_raw.split(",") if part.strip()}
    )
    if _allowlist is not None:
        _log.info(
            "MCP tool allowlist active (%d entries): %s",
            len(_allowlist),
            sorted(_allowlist),
        )

    def _add(fn):
        """Register ``fn`` with FastMCP iff the allowlist permits it.

        Filtering by ``fn.__name__`` matches how OpenClaw's MCP client
        addresses tools (bare name) before applying its own namespace
        prefix. Tools in ``BOOTSTRAP_TOOLS`` are always registered: they
        are called by ``scenario_boot`` before any LLM is involved, and
        the allowlist exists to constrain the *LLM-facing* surface only.
        """
        if (
            _allowlist is None
            or fn.__name__ in _allowlist
            or fn.__name__ in BOOTSTRAP_TOOLS
        ):
            mcp.add_tool(fn)
        else:
            _log.debug(
                "MCP tool %r suppressed by allowlist", fn.__name__
            )

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

    _add(peers_list)

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

    _add(peer_add)

    # ---- Wallet --------------------------------------------------------

    async def wallet_address() -> str:
        """Return this agent's testnet receiving address (bech32)."""
        return agent.wallet.address()

    _add(wallet_address)

    async def wallet_balance() -> int:
        """Return this agent's wallet balance in satoshis (refreshes from network)."""
        return agent.wallet.balance_sats(refresh=True)

    _add(wallet_balance)

    async def wallet_send(to_address: str, sats: int) -> str:
        """Send satoshis to a Bitcoin address. Returns the broadcast txid (hex)."""
        return agent.wallet.send(to_address, sats)

    _add(wallet_send)

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

    _add(seedbox_donate_and_join)

    # ---- Community treasury + signed-log layer -----------------------

    async def community_log_list_recent(limit: int = 50) -> list[dict[str, Any]]:
        """Return recent accepted/rejected community-log entries from local + peer logs."""
        from agent.community_state import COMMUNITY_ACTIONS, replay_community

        manifest = agent.network_manifest
        if manifest is None:
            return []
        all_entries = agent.all_community_entries()
        relevant = [entry for entry in all_entries if entry.get("action") in COMMUNITY_ACTIONS]
        ordered = sorted(
            relevant,
            key=lambda entry: (
                entry.get("timestamp", ""),
                entry.get("reporter_id", ""),
                entry.get("entry_hash", ""),
            ),
        )
        state = replay_community(manifest, ordered)
        accepted_hashes = (
            {donation.entry_hash for donation in state.donations}
            | {purchase.entry_hash for purchase in state.purchases}
            | {provisioned.entry_hash for provisioned in state.provisioned}
        )
        out: list[dict[str, Any]] = []
        for entry in ordered[-max(0, int(limit)):]:
            details = entry.get("details") or {}
            out.append(
                {
                    "action": entry.get("action"),
                    "reporter_id": entry.get("reporter_id"),
                    "timestamp": entry.get("timestamp"),
                    "entry_hash": entry.get("entry_hash"),
                    "amount_sats": details.get("amount_sats"),
                    "cost_sats": details.get("cost_sats"),
                    "purchase_intent_hash": details.get("purchase_intent_hash"),
                    "seedbox_url": details.get("seedbox_url"),
                    "accepted": entry.get("entry_hash") in accepted_hashes,
                }
            )
        return out

    _add(community_log_list_recent)

    def _community_summary() -> dict[str, Any]:
        state = agent.community_state()
        if state is None:
            return {}
        manifest = agent.network_manifest
        me = agent.community_reporter_id
        return {
            "balance_sats": state.balance_sats,
            "member_count": state.member_count,
            "seedbox_count": state.seedbox_count,
            "pending_purchases": state.pending_purchases,
            "threshold_active": state.threshold_active(manifest),
            "my_membership_status": "admitted" if me in state.members else "outsider",
        }

    async def community_treasury_balance() -> dict[str, Any]:
        """Current no-custody treasury balance derived by replaying signed logs."""
        summary = _community_summary()
        if not summary:
            return {"error": "no_manifest_loaded"}
        return summary

    _add(community_treasury_balance)

    async def community_member_count() -> dict[str, Any]:
        """Current admitted-member count plus this node's membership status."""
        summary = _community_summary()
        if not summary:
            return {"error": "no_manifest_loaded"}
        return {
            "member_count": summary["member_count"],
            "my_membership_status": summary["my_membership_status"],
            "threshold_active": summary["threshold_active"],
        }

    _add(community_member_count)

    async def community_donate_and_join(amount_sats: int) -> dict[str, Any]:
        """Append a signed donation_intent entry to this agent's community log."""
        registry = build_tools(agent)
        return await registry.dispatch("community_donate_and_join", {"amount_sats": amount_sats})

    _add(community_donate_and_join)

    async def community_join_via_peer(
        gatekeeper_mid: str,
        amount_sats: int,
        timeout_s: float = 30.0,
    ) -> dict[str, Any]:
        """Ship a signed donation_intent to a gatekeeper peer and await admission."""
        registry = build_tools(agent)
        return await registry.dispatch(
            "community_join_via_peer",
            {
                "gatekeeper_mid": gatekeeper_mid,
                "amount_sats": amount_sats,
                "timeout_s": timeout_s,
            },
        )

    _add(community_join_via_peer)

    async def seedbox_purchase_propose(cost_sats: int | None = None) -> dict[str, Any]:
        """Append a signed seedbox_purchase_intent if growth threshold is active."""
        registry = build_tools(agent)
        args = {} if cost_sats is None else {"cost_sats": cost_sats}
        return await registry.dispatch("seedbox_purchase_propose", args)

    _add(seedbox_purchase_propose)

    async def seedbox_provisioned(
        purchase_intent_hash: str,
        seedbox_url: str,
        seedbox_pubkey_hex: str,
    ) -> dict[str, Any]:
        """Append a signed seedbox_provisioned entry closing a purchase intent."""
        registry = build_tools(agent)
        return await registry.dispatch(
            "seedbox_provisioned",
            {
                "purchase_intent_hash": purchase_intent_hash,
                "seedbox_url": seedbox_url,
                "seedbox_pubkey_hex": seedbox_pubkey_hex,
            },
        )

    _add(seedbox_provisioned)

    # ---- Overlays ------------------------------------------------------

    async def overlays_list() -> list[dict[str, Any]]:
        """List compiled overlays with full per-message field schemas.

        Each entry is ``{community_id_hex, name, version, description,
        messages: [{name, msg_id, fields: [{name, encoding, description}],
        handler_text}], errors, dependencies}``. Read this before calling
        ``overlay_invoke`` so you know each message's field shape.
        """
        from protocol.registry import overlay_to_dict
        return [
            overlay_to_dict(agent.registry._compiled[cid])
            for cid in agent.registry.list_loaded()
        ]

    _add(overlays_list)

    async def overlay_describe(community_id_hex: str) -> dict[str, Any]:
        """Return the canonical markdown of a loaded overlay.

        Use when the structured ``handler_text`` in ``overlays_list`` is
        ambiguous. Capped at 32 KiB; the ``truncated`` flag tells you
        whether the descriptor was clipped. Returns
        ``{"error": "no_canonical_md:python_class"}`` for overlays
        registered via ``register_community(cls)`` — there is no
        canonical text for a hand-written Python class.
        """
        try:
            community_id = bytes.fromhex(community_id_hex)
        except ValueError as exc:
            return {"error": f"bad_hex:{exc}"}
        compiled = agent.registry._compiled.get(community_id)
        if compiled is None:
            return {"error": f"overlay_not_loaded:{community_id_hex}"}
        if compiled.origin == "python_class":
            return {"error": "no_canonical_md:python_class"}
        md_bytes = compiled.canonical_md_bytes
        truncated = False
        if len(md_bytes) > OVERLAY_DESCRIBE_MAX_BYTES:
            md_bytes = md_bytes[:OVERLAY_DESCRIBE_MAX_BYTES]
            truncated = True
        return {
            "community_id_hex": community_id_hex,
            "md_text": md_bytes.decode("utf-8", errors="replace"),
            "truncated": truncated,
            "size_bytes": len(compiled.canonical_md_bytes),
        }

    _add(overlay_describe)

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

    _add(overlay_fetch_and_load)

    async def overlay_publish(md_text: str) -> str:
        """Publish (serve + locally load) a markdown overlay descriptor.

        Returns the 20-byte md_hash as hex.
        """
        md_hash = agent.seedbox.publish_overlay(md_text)
        agent.registry.load(md_text)
        return md_hash.hex()

    _add(overlay_publish)

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
        if (
            compiled.parsed is not None
            and compiled.parsed.identity.get("name") == "content_community"
            and message_name == "SEARCH_RESPONSE"
        ):
            return {
                "error": (
                    "do_not_send_SEARCH_RESPONSE_manually: content seekers must send "
                    "SEARCH_REQUEST; the seedbox handler sends SEARCH_RESPONSE automatically"
                )
            }
        payload_cls = compiled.payload_classes[message_name]
        coerced = [_coerce_field_value(v) for v in fields.values()]
        peer = _resolve_peer(agent, peer_mid)
        instance.ez_send(peer, payload_cls(*coerced))
        return {"sent": True}

    _add(overlay_invoke)

    # ---- Network manifest ----------------------------------------------

    async def agent_inject_manifest(md_text: str) -> dict[str, Any]:
        """Parse + cache a network manifest into this agent's runtime.

        Pre-introduces every genesis peer (skipping self). Idempotent on
        ``network_id``. If this agent is named as a genesis peer, the
        manifest is also published into the bootstrap community so future
        joiners can fetch it via MANIFEST_REQUEST.

        After the manifest is cached, the helper
        ``agent.ensure_default_overlays_loaded`` attempts to wire-fetch
        any descriptor named in ``default_overlays`` that this agent
        does not already hold locally — exercising the
        OVERLAY_REQUEST → OVERLAY_DELIVERY round-trip on the bootstrap
        community. Per-overlay failures are reported via
        ``overlays_loaded`` / ``overlay_errors`` and do not raise: the
        agent's later ``network_join`` will retry.
        """
        from protocol.manifest import ManifestParseError
        try:
            manifest = agent.load_manifest(md_text)
        except ManifestParseError as exc:
            return {"error": f"manifest_parse_failed: {exc}"}
        overlays_loaded, overlay_errors = await agent.ensure_default_overlays_loaded()
        return {
            "network_id_hex": manifest.network_id.hex(),
            "name": manifest.identity.get("name", ""),
            "genesis_peers": len(manifest.genesis_peers),
            "default_overlays": list(manifest.default_overlays),
            "overlays_loaded": overlays_loaded,
            "overlay_errors": overlay_errors,
        }

    _add(agent_inject_manifest)

    async def network_join(manifest_md_text: str | None = None) -> dict[str, Any]:
        """Join the network end-to-end.

        Steps inside the tool:
          1. Parse the provided manifest (or use the cached one).
          2. Pre-introduce every genesis peer (skipping self).
          3. Fetch + compile + register every default overlay from the
             first reachable genesis peer.
          4. ``wallet.send(gatekeeper_address, min_sats)`` — broadcast
             the donation.
          5. ``request_join(primary_peer, txid)`` and await the decision.

        Returns ``{network_id_hex, accepted, overlays_loaded, overlay_errors,
        txid}``. If any stage fails, an ``error`` key surfaces the cause.
        """
        import asyncio
        from protocol.manifest import ManifestParseError

        if manifest_md_text is not None:
            try:
                manifest = agent.load_manifest(manifest_md_text)
            except ManifestParseError as exc:
                return {"error": f"manifest_parse_failed: {exc}"}
        else:
            manifest = agent.network_manifest
            if manifest is None:
                return {"error": "no_manifest_loaded"}

        genesis_pubkey_set = {gp.pubkey_hex.lower() for gp in manifest.genesis_peers}
        genesis_peers = [
            p for p in agent.known_peers()
            if p.public_key.key_to_bin().hex().lower() in genesis_pubkey_set
        ]
        if not genesis_peers:
            return {
                "error": "no_genesis_peers_reachable",
                "network_id_hex": manifest.network_id.hex(),
            }
        primary = genesis_peers[0]

        overlays_loaded: list[str] = []
        overlay_errors: list[dict[str, str]] = []
        for h_hex in manifest.default_overlays:
            h = bytes.fromhex(h_hex)
            if agent.registry.get(h) is not None:
                overlays_loaded.append(h_hex)
                continue
            try:
                fut = agent.seedbox.fetch_overlay(primary, h)
                md_bytes = await asyncio.wait_for(fut, timeout=10)
                agent.registry.load(md_bytes.decode("utf-8"))
                overlays_loaded.append(h_hex)
            except Exception as exc:
                overlay_errors.append({"sha1": h_hex, "error": str(exc)})

        try:
            txid = agent.wallet.send(
                manifest.admission.gatekeeper_address,
                manifest.admission.min_sats,
            )
        except Exception as exc:
            return {
                "error": f"donation_failed: {exc}",
                "network_id_hex": manifest.network_id.hex(),
                "overlays_loaded": overlays_loaded,
                "overlay_errors": overlay_errors,
            }

        try:
            fut = agent.seedbox.request_join(primary, bytes.fromhex(txid))
            accepted = await asyncio.wait_for(fut, timeout=60)
        except Exception as exc:
            return {
                "error": f"join_failed: {exc}",
                "network_id_hex": manifest.network_id.hex(),
                "overlays_loaded": overlays_loaded,
                "overlay_errors": overlay_errors,
                "txid": txid,
            }

        return {
            "network_id_hex": manifest.network_id.hex(),
            "accepted": bool(accepted),
            "overlays_loaded": overlays_loaded,
            "overlay_errors": overlay_errors,
            "txid": txid,
        }

    _add(network_join)

    # ---- BitTorrent ---------------------------------------------------

    async def torrent_seed(path: str) -> str:
        """Begin seeding a local file. Returns the resulting magnet URI."""
        return agent.bittorrent.seed(Path(path))

    _add(torrent_seed)

    async def torrent_fetch(magnet_uri: str, timeout_s: float = 600.0) -> str:
        """Download a magnet URI to local disk; returns the saved path."""
        import asyncio
        future = agent.bittorrent.add_magnet(magnet_uri)
        path = await asyncio.wait_for(future, timeout=timeout_s)
        return str(path)

    _add(torrent_fetch)

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

    _add(torrent_stats)

    # ---- Paper-demo helper: SEARCH + fetch in a single tool ------------

    async def content_search_and_fetch(
        query: str = "",
        timeout_s: float = 10.0,
        pick: str | int = "random",
    ) -> dict[str, Any]:
        """Search content_community peers and fetch one returned magnet.

        Sends a SEARCH_REQUEST on the loaded ``content_community`` overlay
        when ``response_cache`` is empty, waits up to ``timeout_s`` for a
        SEARCH_RESPONSE, then picks one row (``"random"`` by default;
        ``"first"`` or a 0-based integer index also accepted) and downloads
        its magnet via the BitTorrent service. The single watchdog-friendly
        tool for steps 4-5 of the paper-demo storyline; use this instead of
        composing ``overlay_invoke`` + ``torrent_fetch`` by hand.

        Default ``query=""`` matches every entry in the peer's
        ``local_index`` — the content_community handler treats an empty
        query as "return the full catalogue". Pass a non-empty string to
        narrow the search to entries whose ``name`` or ``tags`` contain
        that substring.
        """
        import asyncio
        import random

        compiled_item = None
        overlay = None
        for community_id in agent.registry.list_loaded():
            compiled = agent.registry._compiled[community_id]
            if compiled.parsed is not None and compiled.parsed.identity.get("name") == "content_community":
                compiled_item = compiled
                overlay = agent.registry.get(community_id)
                break
        if compiled_item is None or overlay is None:
            return {"error": "content_community_not_loaded"}

        def matching_rows() -> list[dict[str, Any]]:
            rows = []
            q = query.lower()
            for row in getattr(overlay, "response_cache", []) or []:
                if not isinstance(row, dict):
                    continue
                haystack = " ".join([
                    str(row.get("name", "")),
                    " ".join(str(t) for t in row.get("tags", []) or []),
                    str(row.get("magnet", "")),
                ]).lower()
                if not q or q in haystack or "creative commons" in haystack:
                    rows.append(row)
            return rows

        rows = matching_rows()
        peers = list(agent.known_peers())
        sent = False
        if not rows:
            payload_cls = compiled_item.payload_classes.get("SEARCH_REQUEST")
            if payload_cls is None:
                return {"error": "content_community_missing_SEARCH_REQUEST"}
            if not peers:
                return {"error": "no_known_peers_for_content_search"}
            before = len(getattr(overlay, "response_cache", []) or [])
            for peer in peers:
                _wire_logger.info(
                    "IPv8 send msg=SEARCH_REQUEST peer=%s overlay=content_community via=content_search_and_fetch query=%r",
                    peer.mid.hex()[:12],
                    query,
                )
                overlay.ez_send(peer, payload_cls(query.encode("utf-8")))
            sent = True

            deadline = asyncio.get_running_loop().time() + timeout_s
            while asyncio.get_running_loop().time() < deadline:
                if len(getattr(overlay, "response_cache", []) or []) > before:
                    break
                await asyncio.sleep(0.1)
            rows = matching_rows()

        if not rows:
            return {
                "searched": sent,
                "peer_count": len(peers),
                "response_count": len(getattr(overlay, "response_cache", []) or []),
                "error": "no_matching_content_response",
            }

        if isinstance(pick, int) and 0 <= pick < len(rows):
            chosen = rows[pick]
            pick_mode = f"index_{pick}"
        elif pick == "first":
            chosen = rows[0]
            pick_mode = "first"
        else:
            chosen = random.choice(rows)
            pick_mode = "random"
        magnet = chosen.get("magnet")
        if not magnet:
            return {"error": "matching_content_response_missing_magnet", "result": chosen}
        _wire_logger.info(
            "IPv8 recv msg=SEARCH_RESPONSE peer=? overlay=content_community via=response_cache results=%d pick=%s",
            len(rows),
            pick_mode,
        )
        path = await torrent_fetch(str(magnet), timeout_s=max(timeout_s, 30.0))
        return {
            "searched": sent,
            "peer_count": len(peers),
            "result": chosen,
            "magnet": magnet,
            "download_path": path,
            "pick": pick_mode,
            "result_count": len(rows),
            "torrent_stats": await torrent_stats(),
        }

    _add(content_search_and_fetch)

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
