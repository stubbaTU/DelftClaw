"""Build the watchdog turn-snapshot by MCP-calling the agent's own server.

Replaces the prior architecture in which the watchdog booted a *second*
``OpenClawAgent`` (separate IPv8 instance on ``ipv8_port + 1000``,
separate libtorrent service, separate pull loop) purely to call
``collect_state`` against. That snapshot agent was orphaned from the
real agent's network state — peer cross-introductions, manifests, and
community-log writes all happened on the MCP-process agent, so the
snapshot reported empty peer lists every tick and the LLM had nothing
to act on.

The single-agent model: only the MCP-process ``OpenClawAgent`` exists.
The watchdog drives the LLM via ``openclaw agent`` over MCP, and reads
its own snapshot through the same MCP server. Identity + manifest are
derived locally because they're already on disk (seed file +
``MANIFEST_FILE`` env var) so we don't burn an MCP round-trip for static
data.

The returned dict shape is byte-identical to ``deploy.state_snapshot.
collect_state`` so existing stop predicates + JSONL log replay tooling
keep working unchanged.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from fastmcp import Client

from identity.agent_identity import AgentIdentity
from protocol.manifest import NetworkManifest, parse_manifest


async def _call_mcp(client: Client, tool: str, args: dict | None = None) -> Any:
    """Invoke ``tool`` on the connected MCP client; decode the result.

    FastMCP returns a ``CallToolResult`` whose ``content[0].text`` carries
    the JSON-serialised tool result. We try to decode JSON first and fall
    through to the raw text for tools that return plain strings
    (``wallet_address`` etc.). Tools that return ``{"error": "..."}``
    surface here as a normal dict; callers decide how to handle them.
    """
    result = await client.call_tool(tool, args or {})
    if getattr(result, "content", None):
        text = getattr(result.content[0], "text", "")
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text
    return getattr(result, "structured_content", {}) or {}


async def collect_state_via_mcp(
    *,
    mcp_url: str,
    identity: AgentIdentity,
    ipv8_address: tuple[str, int],
    manifest: NetworkManifest | None,
    timeout_s: float = 10.0,
) -> dict[str, Any]:
    """Build the same dict shape as ``deploy.state_snapshot.collect_state``.

    Network / wallet / community / peers / overlays / torrents are all
    sourced from MCP tool calls against the agent's own server, so the
    snapshot reflects the live state of the only ``OpenClawAgent`` in
    the system. Identity + IPv8 address come from local materials —
    they don't change tick-to-tick and don't need a network round-trip.
    """
    async with asyncio.timeout(timeout_s):
        async with Client(mcp_url) as client:
            wallet_address_raw = await _call_mcp(client, "wallet_address")
            wallet_balance_raw = await _call_mcp(client, "wallet_balance")
            community_raw = await _call_mcp(client, "community_treasury_balance")
            peers_raw = await _call_mcp(client, "peers_list")
            overlays_raw = await _call_mcp(client, "overlays_list")
            torrents_raw = await _call_mcp(client, "torrent_stats")

    return {
        "ts": time.time(),
        "agent": {
            "agent_id": str(identity.agent_id),
            "pubkey_hex": identity.ipv8.pubkey.hex(),
            "ipv8_address": list(ipv8_address),
            "wallet_address": (
                wallet_address_raw if isinstance(wallet_address_raw, str)
                else str(wallet_address_raw)
            ),
        },
        "network": _network_section(manifest),
        "wallet": _wallet_section(wallet_address_raw, wallet_balance_raw),
        "community": _community_section(community_raw),
        "peers": _peers_section(peers_raw),
        "overlays": _overlays_section(overlays_raw),
        "torrents": _torrents_section(torrents_raw),
    }


# ---------------------------------------------------------------------------
# Per-section builders — keep the legacy dict shape so stop predicates,
# JSONL log replay, and the existing turn_builder all keep working.
# ---------------------------------------------------------------------------

def _network_section(manifest: NetworkManifest | None) -> dict[str, Any] | None:
    """Manifest summary parsed from disk — never via MCP, the manifest is static."""
    if manifest is None:
        return None
    return {
        "network_id_hex": manifest.network_id.hex(),
        "name": manifest.identity.get("name", ""),
        "version": manifest.identity.get("version", ""),
        "description": manifest.identity.get("description", ""),
        "admission": {
            "gatekeeper_address": manifest.admission.gatekeeper_address,
            "min_sats": manifest.admission.min_sats,
            "min_confirmations": manifest.admission.min_confirmations,
            "bootstrap_cap_sats": manifest.admission.effective_bootstrap_cap_sats,
            "max_agents_per_seedbox": manifest.admission.max_agents_per_seedbox,
            "seedbox_cost_sats": manifest.admission.seedbox_cost_sats,
        },
        "genesis_peers": [
            {"host": gp.host, "port": gp.port, "pubkey_hex": gp.pubkey_hex}
            for gp in manifest.genesis_peers
        ],
        "default_overlays": list(manifest.default_overlays),
    }


def _wallet_section(address_raw: Any, balance_raw: Any) -> dict[str, Any]:
    address = address_raw if isinstance(address_raw, str) else str(address_raw)
    if isinstance(balance_raw, int):
        return {"address": address, "balance_sats": balance_raw}
    if isinstance(balance_raw, dict) and "error" in balance_raw:
        return {"address": address, "balance_sats": None,
                "error": str(balance_raw["error"])}
    # ``wallet_balance`` returns a bare int; anything else (e.g. a string
    # number) is best-effort coerced for the JSONL log's sake.
    try:
        return {"address": address, "balance_sats": int(balance_raw)}
    except (TypeError, ValueError):
        return {"address": address, "balance_sats": None,
                "error": f"non_integer_balance:{balance_raw!r}"}


def _community_section(raw: Any) -> dict[str, Any] | None:
    """``community_treasury_balance`` returns the right shape already."""
    if not isinstance(raw, dict):
        return None
    if "error" in raw:
        # ``no_manifest_loaded`` — surface as null to match the legacy
        # shape (the agent has no community to score yet).
        return None
    return {
        "balance_sats": int(raw.get("balance_sats", 0)),
        "member_count": int(raw.get("member_count", 0)),
        "seedbox_count": int(raw.get("seedbox_count", 0)),
        "pending_purchases": int(raw.get("pending_purchases", 0)),
        "threshold_active": bool(raw.get("threshold_active", False)),
        "my_membership_status": str(raw.get("my_membership_status", "outsider")),
    }


def _peers_section(raw: Any) -> list[dict[str, Any]]:
    """Per-peer view. ``peers_list`` returns mid_hex+address only — the
    PEER_INTRO-derived ``wallet_address`` / ``known_overlays`` fields are
    not exposed by that tool, so we report ``None`` / ``[]``. Genesis
    peers (with full coords) live in ``state.network.genesis_peers`` for
    the LLM to consult.
    """
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        out.append({
            "mid_hex": entry.get("mid_hex"),
            "address": entry.get("address"),
            "wallet_address": None,
            "known_overlays": [],
        })
    return out


def _overlays_section(raw: Any) -> list[dict[str, Any]]:
    """``overlays_list`` already returns the rich per-message structure
    the LLM consumes. We trim the prose-heavy ``handler_text`` /
    ``description`` fields to match the prior snapshot's token budget
    (the legacy state_snapshot stripped handler text for the same
    reason — operators read overlays via ``overlay_describe`` when they
    need the full markdown).
    """
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for ov in raw:
        if not isinstance(ov, dict):
            continue
        entry: dict[str, Any] = {
            "community_id_hex": ov.get("community_id_hex"),
            "origin": ov.get("origin", "markdown"),
            "name": ov.get("name", ""),
            "version": ov.get("version", ""),
            "messages": [
                {
                    "name": m.get("name"),
                    "msg_id": m.get("msg_id"),
                    "fields": [
                        {"name": f.get("name"), "encoding": f.get("encoding")}
                        for f in (m.get("fields") or [])
                        if isinstance(f, dict)
                    ],
                }
                for m in (ov.get("messages") or [])
                if isinstance(m, dict)
            ],
        }
        # Pass through anything the overlay has received from peers
        # (e.g. SEARCH_RESPONSE hits in content_community.response_cache).
        # This is the bridge that lets an agent which fired SEARCH on a
        # prior turn see the result in THIS turn's prompt and then
        # torrent_fetch it (concept step 5). Keep it verbatim — the
        # magnet/name/size the agent needs are inside.
        if isinstance(ov.get("received"), list) and ov["received"]:
            entry["received"] = ov["received"]
        out.append(entry)
    return out


def _torrents_section(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for t in raw:
        if not isinstance(t, dict):
            continue
        out.append({
            "magnet": t.get("magnet"),
            "name": t.get("name"),
            "progress": float(t.get("progress", 0.0)),
            "seeding": bool(t.get("seeding", False)),
            "save_path": t.get("save_path"),
            "peers": int(t.get("peers", 0)),
        })
    return out


# ---------------------------------------------------------------------------
# Convenience: parse the on-disk manifest once at watchdog startup
# ---------------------------------------------------------------------------

def load_manifest_from_file(path: Path) -> NetworkManifest | None:
    """Return the parsed manifest from ``path`` or ``None`` on any failure.

    The watchdog calls this once at boot and reuses the result for every
    snapshot. ``scenario_boot.py`` writes the manifest to disk at boot
    time so this is a cheap synchronous read. Logs at WARNING when a
    file exists but doesn't parse so the operator can see immediately
    that ``state.network`` will be null in the prompts — which is what
    causes the LLM to hallucinate manifest re-injection calls (caught
    in the 20:33+ seek_cc run).
    """
    import logging
    _log = logging.getLogger("watchdog.manifest")

    if not path.is_file():
        _log.warning("manifest file does not exist: %s", path)
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        _log.warning("manifest file %s unreadable: %s: %s",
                     path, type(exc).__name__, exc)
        return None
    try:
        return parse_manifest(text)
    except Exception as exc:
        # Quote the first 200 chars of the file so the operator can
        # see what the parser is rejecting without having to ssh in
        # and `sudo cat` the file.
        snippet = text[:200].replace("\n", "\\n")
        _log.warning("manifest file %s did NOT parse: %s: %s | head=%r",
                     path, type(exc).__name__, exc, snippet)
        return None
