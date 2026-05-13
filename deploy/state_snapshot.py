"""``collect_state(agent) -> dict`` — the typed snapshot the watchdog hands to the LLM and to stop predicates.

The snapshot is intentionally:

  * **Read-only** — no IPv8 packets sent, no wallet broadcasts. Safe to
    invoke on every watchdog tick.
  * **JSON-serialisable** — every value is a builtin (``int``, ``str``,
    ``list``, ``dict``, ``bool``, ``None``). The watchdog renders the
    snapshot into the LLM prompt and into a JSONL log line; both need a
    deterministic representation.
  * **Stable shape** — same keys whether the agent is healthy or
    half-initialised. Tests + stop predicates depend on the shape.
"""

from __future__ import annotations

import time
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from agent.runtime import OpenClawAgent


def collect_state(agent: "OpenClawAgent") -> dict[str, Any]:
    """Capture an atomic, JSON-serialisable picture of ``agent``'s view of the network."""
    return {
        "ts": time.time(),
        "agent": {
            "agent_id": str(agent.identity.agent_id),
            "pubkey_hex": agent.pubkey_hex,
            "ipv8_address": list(agent.address),
            "wallet_address": agent.wallet.address(),
        },
        "network": _network_snapshot(agent),
        "wallet": _wallet_snapshot(agent),
        "peers": _peers_snapshot(agent),
        "overlays": _overlays_snapshot(agent),
        "torrents": _torrents_snapshot(agent),
    }


def _network_snapshot(agent: "OpenClawAgent") -> dict[str, Any] | None:
    """Manifest summary for the LLM, or ``None`` when no manifest is loaded."""
    manifest = agent.network_manifest
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
        },
        "genesis_peers": [
            {"host": gp.host, "port": gp.port, "pubkey_hex": gp.pubkey_hex}
            for gp in manifest.genesis_peers
        ],
        "default_overlays": list(manifest.default_overlays),
    }


def _wallet_snapshot(agent: "OpenClawAgent") -> dict[str, Any]:
    """Read-only wallet view. Never refreshes — that's the LLM's job via ``wallet_balance``."""
    try:
        balance_sats = agent.wallet.balance_sats(refresh=False)
    except Exception as exc:
        return {"address": agent.wallet.address(), "balance_sats": None,
                "error": f"{type(exc).__name__}: {exc}"}
    return {"address": agent.wallet.address(), "balance_sats": int(balance_sats)}


def _peers_snapshot(agent: "OpenClawAgent") -> list[dict[str, Any]]:
    """Per-peer view including the live ``PEER_INTRO`` metadata when available."""
    out: list[dict[str, Any]] = []
    # PeerMeta entries are keyed by peer.mid; the bootstrap community owns them.
    peer_meta = agent.seedbox.peer_meta if agent.seedbox else {}
    for peer in agent.known_peers():
        addr = list(peer.addresses.values())[0] if peer.addresses else None
        entry: dict[str, Any] = {
            "mid_hex": peer.mid.hex(),
            "address": list(addr) if addr is not None else None,
            "wallet_address": None,
            "known_overlays": [],
        }
        meta = peer_meta.get(peer.mid)
        if meta is not None:
            entry["wallet_address"] = meta.wallet_address
            entry["known_overlays"] = [h.hex() for h in meta.known_overlays]
        out.append(entry)
    return out


def _overlays_snapshot(agent: "OpenClawAgent") -> list[dict[str, Any]]:
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


def _torrents_snapshot(agent: "OpenClawAgent") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for t in agent.bittorrent.stats():
        out.append({
            "magnet": t.magnet,
            "name": t.name,
            "progress": float(t.progress),
            "seeding": bool(t.seeding),
            "save_path": str(t.save_path) if t.save_path else None,
            "peers": int(t.peers),
        })
    return out
