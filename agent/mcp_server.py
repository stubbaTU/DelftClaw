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
  - **The compiler LLM** (Claude, reached via the local LLM proxy) —
    called by ``OverlayRegistry`` *only* when this node needs to
    compile a ``.md`` overlay descriptor it has never seen before.
    Configured via ``--llm-base-url`` / ``--llm-model`` on the agent
    side. Never talks to OpenClaw.

Boot via ``python -m agent ... mcp --mcp-host 0.0.0.0 --mcp-port 8765``.
"""

from __future__ import annotations

import functools
import logging
import os
import time
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from agent.runtime import OpenClawAgent
from agent.tools import (  # type: ignore[attr-defined]
    _resolve_peer,
    _short,
    _tool_logger,
    build_tools,
)
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
  - community_donate_and_join — admission: self-append a signed donation_intent
    to your own log; every member admits you by replaying the signed logs (no
    gatekeeper key). Use once state.network is set but you have not yet joined.
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

        Each registered tool is wrapped with a tool-call audit logger that
        emits the same ``TOOL call name=… args=…`` / ``TOOL ok name=…`` /
        ``TOOL fail name=…`` lines on the ``delftclaw.agent.tools`` logger
        that ``agent.tools.ToolRegistry.dispatch`` produces for the
        direct-driver path. Without this wrapper, MCP-served scenarios
        emit zero tool-call audit lines — ``make tools`` /
        ``make tools-summary`` / the ``deploy.trace`` tool histogram
        showed "no tool calls in journal" for the entire community_demo
        + file_share lineup, even though the MCP service was definitely
        dispatching tools.

        Filtering by ``fn.__name__`` matches how OpenClaw's MCP client
        addresses tools (bare name) before applying its own namespace
        prefix. Tools in ``BOOTSTRAP_TOOLS`` are always registered: they
        are called by ``scenario_boot`` before any LLM is involved, and
        the allowlist exists to constrain the *LLM-facing* surface only.
        """
        if not (
            _allowlist is None
            or fn.__name__ in _allowlist
            or fn.__name__ in BOOTSTRAP_TOOLS
        ):
            _log.debug("MCP tool %r suppressed by allowlist", fn.__name__)
            return

        tool_name = fn.__name__

        @functools.wraps(fn)
        async def _audited(**kwargs):
            t0 = time.monotonic()
            _tool_logger.info("TOOL call name=%s args=%s", tool_name, _short(kwargs))
            try:
                result = await fn(**kwargs)
            except Exception as exc:
                _tool_logger.warning(
                    "TOOL fail name=%s elapsed=%.3fs error=%s: %s",
                    tool_name, time.monotonic() - t0, type(exc).__name__, exc,
                )
                raise
            _tool_logger.info(
                "TOOL ok   name=%s elapsed=%.3fs result=%s",
                tool_name, time.monotonic() - t0, _short(result),
            )
            return result

        mcp.add_tool(_audited)

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
        accepted_hashes = {donation.entry_hash for donation in state.donations}
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
                    "accepted": entry.get("entry_hash") in accepted_hashes,
                }
            )
        return out

    _add(community_log_list_recent)

    def _community_summary() -> dict[str, Any]:
        state = agent.community_state()
        if state is None:
            return {}
        me = agent.community_reporter_id
        return {
            "balance_sats": state.balance_sats,
            "member_count": state.member_count,
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

    async def request_payment(amount_sats: int, memo: str = "") -> dict[str, Any]:
        """Broadcast a PAYMENT_REQUEST for amount_sats to every known peer."""
        registry = build_tools(agent)
        return await registry.dispatch(
            "request_payment", {"amount_sats": amount_sats, "memo": memo}
        )

    _add(request_payment)

    async def send_payment(to_peer_mid: str, amount_sats: int) -> dict[str, Any]:
        """Send fake BTC to a peer: wallet debit + signed payment entry + notify."""
        registry = build_tools(agent)
        return await registry.dispatch(
            "send_payment", {"to_peer_mid": to_peer_mid, "amount_sats": amount_sats}
        )

    _add(send_payment)

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

        Returns {community_id_hex, loaded}. ``aload`` (not ``load``) so the
        multi-second live compile runs off the event loop, and
        ``provenance="received_from:<peer>"`` so the per-demo archive attributes
        this agent as an ADOPTER (matching agent/tools.py — kept in sync to
        avoid the drift that left this copy on the stale code path).
        """
        import asyncio
        peer = _resolve_peer(agent, peer_mid)
        md_hash = bytes.fromhex(md_hash_hex)
        future = agent.seedbox.fetch_overlay(peer, md_hash)
        md_bytes = await asyncio.wait_for(future, timeout=10)
        instance = await agent.registry.aload(
            md_bytes.decode("utf-8"),
            provenance=f"received_from:{peer.mid.hex()[:12]}",
        )
        cid_hex = instance.community_id.hex()
        # Wake peers — mirrors agent/tools.py::overlay_fetch_and_load (see
        # project-mcp-tool-drift memory; this file IS the deployed path).
        from agent.wake_signal import signal_peers
        signal_peers(f"overlay_adopted:{cid_hex[:12]}")
        return {"community_id_hex": cid_hex, "loaded": True}

    _add(overlay_fetch_and_load)

    async def overlay_publish(md_text: str) -> str:
        """Publish (serve + locally load) a markdown overlay descriptor.

        Returns the 20-byte md_hash as hex. ``aload`` + ``provenance="published"``
        so the compile runs off the event loop and the archive attributes this
        agent as the publisher (matching agent/tools.py).
        """
        md_hash = agent.seedbox.publish_overlay(md_text)
        await agent.registry.aload(md_text, provenance="published")
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
        # Cross-process counter: lets the watchdog snapshot's
        # ``announce_pending`` rule clear once the agent has sent at least one
        # message on its self-authored protocol (matches the in-process tool).
        from agent.tools import _maybe_record_self_authored_announce  # type: ignore[attr-defined]
        _maybe_record_self_authored_announce(agent, community_id, message_name)
        # Wake peers — mirrors agent/tools.py::overlay_invoke.
        from agent.wake_signal import signal_peers
        signal_peers(f"overlay_message:{message_name}")
        return {"sent": True}

    _add(overlay_invoke)

    # ---- Network manifest ----------------------------------------------

    async def agent_inject_manifest(md_text: str) -> dict[str, Any]:
        """Parse + cache a network manifest into this agent's runtime.

        Pre-introduces every genesis peer (skipping self). Idempotent on
        ``network_id``.

        After the manifest is cached, the helper
        ``agent.ensure_default_overlays_loaded`` attempts to wire-fetch
        any descriptor named in ``default_overlays`` that this agent
        does not already hold locally — exercising the
        OVERLAY_REQUEST → OVERLAY_DELIVERY round-trip on the bootstrap
        community. Per-overlay failures are reported via
        ``overlays_loaded`` / ``overlay_errors`` and do not raise.
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
        """Search content_community peers, fetch one matching file over IPv8.

        Sends a SEARCH_REQUEST on the loaded ``content_community`` overlay,
        waits up to ``timeout_s`` for SEARCH_RESPONSE, narrows to rows whose
        ``name`` or ``tags`` substring-match ``query``, picks one
        (``"random"`` / ``"first"`` / int index), then fetches its bytes
        from a peer via the ``SeedboxCommunity`` CONTENT_REQUEST/DELIVERY
        path, verifies ``sha1(bytes) == magnet btih`` and the catalogue
        size, writes the file into the agent's BitTorrent ``save_dir``, and
        registers the completion so ``torrent_progress_gte_1`` fires on a
        real download.

        Implementation lives in ``agent.content_fetch`` — the same module
        ``agent.tools`` delegates to, so MCP-served scenarios and direct
        in-process drivers share one hash-verified transport (no drift).
        """
        from agent.content_fetch import content_search_and_fetch_impl
        return await content_search_and_fetch_impl(
            agent, query=query, timeout_s=timeout_s, pick=pick,
        )

    _add(content_search_and_fetch)

    async def content_fetch_via_transfer(
        query: str = "",
        timeout_s: float = 20.0,
        pick: str | int = "random",
    ) -> dict[str, Any]:
        """Like ``content_search_and_fetch``, but transfer the file over the
        ``file_transfer`` overlay (chunked: manifest -> numbered CHUNKs ->
        reassembly -> whole-content sha256 verify) instead of the single-shot
        ``SeedboxCommunity`` CONTENT_REQUEST/DELIVERY path. Same discovery and
        ``pick`` semantics. Implementation lives in ``agent.content_fetch`` so
        the in-process and MCP-served paths share it (no drift).
        """
        from agent.content_fetch import content_fetch_via_transfer_impl
        return await content_fetch_via_transfer_impl(
            agent, query=query, timeout_s=timeout_s, pick=pick,
        )

    _add(content_fetch_via_transfer)

    # ---- Overlay authoring: agents introduce new protocol versions ------

    async def overlay_author_and_publish(
        name: str,
        version: str,
        description: str,
        messages: list[dict[str, Any]],
        change_summary: str,
        runtime_state: list[dict[str, Any]] | None = None,
        constants: list[dict[str, Any]] | None = None,
        samples: dict[str, Any] | None = None,
        supersedes_cid_hex: str | None = None,
    ) -> dict[str, Any]:
        """Author a NEW overlay protocol spec and publish it to the network.

        You describe the protocol as structured JSON: ``messages`` is a list of
        ``{name (SCREAMING_SNAKE_CASE), msg_id (0-255), fields: [{name
        (snake_case), encoding, description}], handler (prose)}``. Valid
        encodings: uint8, uint16-be, uint32-be, uint64-be, bool, varlenH,
        varlenH-utf8, varlenH-msgpack, bytes20, bytes32. Optionally pass
        ``runtime_state`` ([{name, type, description}]), ``samples``
        ({MESSAGE_NAME: {field: example}}), and ``supersedes_cid_hex`` (the
        40-char community_id of a loaded same-name overlay this version
        replaces). The tool synthesizes the markdown descriptor with byte-exact
        test vectors, compiles + installs it locally, archives it, and offers it
        to every peer so they can adopt it.

        Implementation lives in ``agent.overlay_authoring_tool`` — shared with
        the in-process tool surface so the two can't drift.
        """
        from agent.overlay_authoring_tool import overlay_author_and_publish_impl
        return await overlay_author_and_publish_impl(
            agent, name=name, version=version, description=description,
            messages=messages, change_summary=change_summary,
            runtime_state=runtime_state, constants=constants, samples=samples,
            supersedes_cid_hex=supersedes_cid_hex,
        )

    _add(overlay_author_and_publish)

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
