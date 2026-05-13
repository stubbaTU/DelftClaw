"""Tool surface the LLM tool-call loop dispatches into.

Each tool is a thin sync/async function over the ``OpenClawAgent``
runtime. The ``Tool`` dataclass pairs the callable with an OpenAI-style
JSON schema describing its parameters. ``ToolRegistry.specs()`` produces
the ``tools=[...]`` array for an OpenAI-compatible chat-completions call;
``ToolRegistry.dispatch(name, args)`` runs the named tool against the
agent and returns a JSON-serialisable result.

Tools are intentionally small. Composition (e.g. "donate then join")
lives in the LLM loop's reasoning, not in glue code.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from ipv8.peer import Peer

from agent.runtime import OpenClawAgent
from communication.community import overlay_id


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]              # OpenAI-style JSON schema
    fn: Callable[..., Awaitable[Any]]       # always async; sync tools wrap themselves

    def spec(self) -> dict[str, Any]:
        """OpenAI-compatible function-tool spec."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class ToolRegistry:
    """Looks up and dispatches tools by name."""

    def __init__(self, tools: list[Tool]) -> None:
        self._tools = {t.name: t for t in tools}

    def specs(self) -> list[dict[str, Any]]:
        return [t.spec() for t in self._tools.values()]

    def names(self) -> list[str]:
        return list(self._tools.keys())

    async def dispatch(self, name: str, args: dict[str, Any]) -> Any:
        if name not in self._tools:
            return {"error": f"unknown_tool:{name}"}
        try:
            return await self._tools[name].fn(**args)
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Helper: peer lookup by mid (hex prefix matching)
# ---------------------------------------------------------------------------

def _resolve_peer(agent: OpenClawAgent, mid_hex_prefix: str) -> Peer:
    """Find a known peer by hex prefix of its mid (8 chars or more)."""
    needle = bytes.fromhex(mid_hex_prefix.lower()) if len(mid_hex_prefix) % 2 == 0 \
        else bytes.fromhex(mid_hex_prefix.lower() + "0")
    for peer in agent.known_peers():
        if peer.mid.startswith(needle):
            return peer
    raise KeyError(f"no peer with mid prefix {mid_hex_prefix!r}")


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def build_tools(agent: OpenClawAgent) -> ToolRegistry:
    """Construct the tool registry bound to ``agent``."""

    # ---- Peers ---------------------------------------------------------

    async def peers_list() -> list[dict[str, Any]]:
        return [
            {
                "mid_hex": p.mid.hex(),
                "address": list(p.addresses.values())[0] if p.addresses else None,
            }
            for p in agent.known_peers()
        ]

    async def peer_add(host: str, port: int, pubkey_hex: str) -> dict[str, Any]:
        peer = agent.add_peer(host, port, pubkey_hex)
        return {
            "mid_hex": peer.mid.hex(),
            "address": list(peer.addresses.values())[0] if peer.addresses else None,
        }

    # ---- Wallet --------------------------------------------------------

    async def wallet_address() -> str:
        return agent.wallet.address()

    async def wallet_balance() -> int:
        return agent.wallet.balance_sats(refresh=True)

    async def wallet_send(to_address: str, sats: int) -> str:
        return agent.wallet.send(to_address, sats)

    # ---- Seedbox admission --------------------------------------------

    async def seedbox_donate_and_join(
        gatekeeper_mid: str, sats: int, gatekeeper_address: str
    ) -> dict[str, Any]:
        """Send ``sats`` to ``gatekeeper_address`` then JOIN_REQUEST the gatekeeper."""
        peer = _resolve_peer(agent, gatekeeper_mid)
        txid = agent.wallet.send(gatekeeper_address, sats)
        future = agent.seedbox.request_join(peer, bytes.fromhex(txid))
        accepted = await asyncio.wait_for(future, timeout=60)
        return {"txid": txid, "accepted": bool(accepted)}

    # ---- Overlays ------------------------------------------------------

    async def overlays_list() -> list[dict[str, Any]]:
        """Full per-overlay spec the LLM needs to invoke any message zero-shot.

        Drains everything ``CompiledOverlay.parsed`` already holds —
        identity, every message's field encodings + handler text, error
        policies, dependencies. Without this, the LLM has only message
        names and would have to guess field shapes.
        """
        out: list[dict[str, Any]] = []
        for community_id in agent.registry.list_loaded():
            compiled = agent.registry._compiled[community_id]
            out.append({
                "community_id_hex": community_id.hex(),
                "name": compiled.parsed.identity.get("name", ""),
                "version": compiled.parsed.identity.get("version", ""),
                "description": compiled.parsed.identity.get("description", ""),
                "messages": [
                    {
                        "name": m.name,
                        "msg_id": m.msg_id,
                        "fields": [
                            {
                                "name": f.name,
                                "encoding": f.encoding,
                                "description": f.description,
                            }
                            for f in m.fields
                        ],
                        "handler_text": m.handler_text,
                    }
                    for m in compiled.parsed.messages
                ],
                "errors": [dict(e) for e in compiled.parsed.errors],
                "dependencies": list(compiled.parsed.dependencies),
            })
        return out

    OVERLAY_DESCRIBE_MAX_BYTES = 32 * 1024

    async def overlay_describe(community_id_hex: str) -> dict[str, Any]:
        """Return the canonical markdown of a loaded overlay (truncated if oversized)."""
        try:
            community_id = bytes.fromhex(community_id_hex)
        except ValueError as exc:
            return {"error": f"bad_hex:{exc}"}
        compiled = agent.registry._compiled.get(community_id)
        if compiled is None:
            return {"error": f"overlay_not_loaded:{community_id_hex}"}
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

    async def overlay_fetch_and_load(peer_mid: str, md_hash_hex: str) -> dict[str, Any]:
        peer = _resolve_peer(agent, peer_mid)
        md_hash = bytes.fromhex(md_hash_hex)
        future = agent.seedbox.fetch_overlay(peer, md_hash)
        md_bytes = await asyncio.wait_for(future, timeout=10)
        instance = agent.registry.load(md_bytes.decode("utf-8"))
        return {
            "community_id_hex": instance.community_id.hex(),
            "loaded": True,
        }

    async def overlay_publish(md_text: str) -> str:
        md_hash = agent.seedbox.publish_overlay(md_text)
        # Also load it locally so we serve traffic on the new overlay.
        agent.registry.load(md_text)
        return md_hash.hex()

    # ---- Network manifest -----------------------------------------------

    async def agent_inject_manifest(md_text: str) -> dict[str, Any]:
        """Parse + cache a network manifest into this agent's runtime.

        Pre-introduces every genesis peer (skipping self). Idempotent on
        ``network_id``. Used by ``scenario_boot`` to hand a freshly-
        generated manifest to a joining agent, and by the LLM after a
        MANIFEST_DELIVERY round-trip.
        """
        from protocol.manifest import ManifestParseError

        try:
            manifest = agent.load_manifest(md_text)
        except ManifestParseError as exc:
            return {"error": f"manifest_parse_failed: {exc}"}
        return {
            "network_id_hex": manifest.network_id.hex(),
            "name": manifest.identity.get("name", ""),
            "genesis_peers": len(manifest.genesis_peers),
            "default_overlays": list(manifest.default_overlays),
        }

    async def network_join(manifest_md_text: str | None = None) -> dict[str, Any]:
        """Join the network end-to-end. Uses the cached manifest when no
        ``manifest_md_text`` is given; otherwise loads the provided one first.

        Inside the tool: pre-introduce genesis peers, fetch + compile
        every default overlay, donate the required satoshis, send a
        JOIN_REQUEST, and await the gatekeeper's decision.

        Composition is wrapped in a single tool because joining a
        network is a single semantic act: parse-peer-fetch-donate-join
        is the only sensible order. The lower-level tools remain
        available for the LLM that wants explicit decomposition.
        """
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

        # Pick the first reachable genesis peer (the one IPv8 has accepted
        # after load_manifest's add_peer() round). All admission + overlay
        # traffic goes through this peer.
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

        # Fetch + compile every default overlay.
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

        # Donate the required satoshis on-chain.
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

        # JOIN_REQUEST + await gatekeeper's decision.
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

    async def overlay_invoke(
        community_id_hex: str, message_name: str, peer_mid: str, fields: dict[str, Any]
    ) -> dict[str, Any]:
        """Send a message on a compiled overlay. ``fields`` map JSON values to wire bytes."""
        community_id = bytes.fromhex(community_id_hex)
        instance = agent.registry.get(community_id)
        if instance is None:
            return {"error": f"overlay_not_loaded:{community_id_hex}"}
        compiled = agent.registry._compiled[community_id]
        if message_name not in compiled.payload_classes:
            return {"error": f"unknown_message:{message_name}"}
        payload_cls = compiled.payload_classes[message_name]

        from protocol.compiler import _coerce_field_value  # type: ignore[attr-defined]
        coerced = [_coerce_field_value(v) for v in fields.values()]
        peer = _resolve_peer(agent, peer_mid)
        instance.ez_send(peer, payload_cls(*coerced))
        return {"sent": True}

    # ---- BitTorrent ---------------------------------------------------

    async def torrent_seed(path: str) -> str:
        return agent.bittorrent.seed(Path(path))

    async def torrent_fetch(magnet_uri: str, timeout_s: float = 600.0) -> str:
        future = agent.bittorrent.add_magnet(magnet_uri)
        path = await asyncio.wait_for(future, timeout=timeout_s)
        return str(path)

    async def torrent_stats() -> list[dict[str, Any]]:
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

    # ---- Spec definitions ---------------------------------------------

    P_NONE = {"type": "object", "properties": {}, "additionalProperties": False}

    return ToolRegistry([
        Tool("peers_list",
             "List peers verified on any overlay this agent runs.",
             P_NONE, peers_list),

        Tool("peer_add",
             "Introduce a peer to this agent's IPv8 network at runtime.",
             {"type": "object",
              "properties": {
                  "host": {"type": "string", "description": "remote peer's IPv8 UDP host"},
                  "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                  "pubkey_hex": {"type": "string",
                                  "description": "remote peer's serialised IPv8 public key (74 hex chars)"},
              },
              "required": ["host", "port", "pubkey_hex"],
              "additionalProperties": False},
             peer_add),

        Tool("wallet_address",
             "Return this agent's testnet receiving address.",
             P_NONE, wallet_address),

        Tool("wallet_balance",
             "Return this agent's wallet balance in satoshis (refreshes from network).",
             P_NONE, wallet_balance),

        Tool("wallet_send",
             "Send satoshis to a Bitcoin address. Returns the broadcast txid (hex).",
             {"type": "object",
              "properties": {
                  "to_address": {"type": "string"},
                  "sats": {"type": "integer", "minimum": 1},
              },
              "required": ["to_address", "sats"],
              "additionalProperties": False},
             wallet_send),

        Tool("seedbox_donate_and_join",
             "Donate satoshis to a gatekeeper's address, then send JOIN_REQUEST so they admit us.",
             {"type": "object",
              "properties": {
                  "gatekeeper_mid": {"type": "string", "description": "hex prefix of the gatekeeper's IPv8 mid"},
                  "sats": {"type": "integer", "minimum": 1},
                  "gatekeeper_address": {"type": "string", "description": "BTC address of the seedbox"},
              },
              "required": ["gatekeeper_mid", "sats", "gatekeeper_address"],
              "additionalProperties": False},
             seedbox_donate_and_join),

        Tool("overlays_list",
             "List compiled overlays loaded locally with full per-message field "
             "schemas + handler text. Read this before calling overlay_invoke.",
             P_NONE, overlays_list),

        Tool("overlay_describe",
             "Return the canonical markdown spec of a loaded overlay. Use when "
             "the structured handler_text in overlays_list is ambiguous.",
             {"type": "object",
              "properties": {"community_id_hex": {"type": "string"}},
              "required": ["community_id_hex"],
              "additionalProperties": False},
             overlay_describe),

        Tool("overlay_fetch_and_load",
             "Ask a peer for an overlay descriptor by md_hash, then compile + register it locally.",
             {"type": "object",
              "properties": {
                  "peer_mid": {"type": "string"},
                  "md_hash_hex": {"type": "string", "description": "20-byte hash, hex-encoded"},
              },
              "required": ["peer_mid", "md_hash_hex"],
              "additionalProperties": False},
             overlay_fetch_and_load),

        Tool("overlay_publish",
             "Publish (serve + locally load) a markdown overlay descriptor. Returns its md_hash hex.",
             {"type": "object",
              "properties": {"md_text": {"type": "string"}},
              "required": ["md_text"],
              "additionalProperties": False},
             overlay_publish),

        Tool("agent_inject_manifest",
             "Parse + cache a network manifest markdown into this agent. "
             "Pre-introduces every genesis peer. Returns network_id and "
             "summary; idempotent on network_id.",
             {"type": "object",
              "properties": {"md_text": {"type": "string"}},
              "required": ["md_text"],
              "additionalProperties": False},
             agent_inject_manifest),

        Tool("network_join",
             "Join the network end-to-end: pre-introduce genesis peers, "
             "fetch default overlays, donate, and send JOIN_REQUEST. Uses "
             "the cached manifest unless 'manifest_md_text' is given.",
             {"type": "object",
              "properties": {"manifest_md_text": {"type": "string"}},
              "additionalProperties": False},
             network_join),

        Tool("overlay_invoke",
             "Send a message defined by a compiled overlay to a peer.",
             {"type": "object",
              "properties": {
                  "community_id_hex": {"type": "string"},
                  "message_name": {"type": "string"},
                  "peer_mid": {"type": "string"},
                  "fields": {"type": "object", "description": "field_name -> value (str, int, list, dict)"},
              },
              "required": ["community_id_hex", "message_name", "peer_mid", "fields"],
              "additionalProperties": False},
             overlay_invoke),

        Tool("torrent_seed",
             "Begin seeding a local file. Returns the resulting magnet URI.",
             {"type": "object",
              "properties": {"path": {"type": "string"}},
              "required": ["path"],
              "additionalProperties": False},
             torrent_seed),

        Tool("torrent_fetch",
             "Download a magnet URI to local disk; returns the saved path.",
             {"type": "object",
              "properties": {
                  "magnet_uri": {"type": "string"},
                  "timeout_s": {"type": "number", "default": 600.0},
              },
              "required": ["magnet_uri"],
              "additionalProperties": False},
             torrent_fetch),

        Tool("torrent_stats",
             "Snapshot of all currently-known torrents (downloads + seeds).",
             P_NONE, torrent_stats),
    ])
