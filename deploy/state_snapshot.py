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

import json
import os
import time
from pathlib import Path
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
        "community": _community_snapshot(agent),
        "peers": _peers_snapshot(agent),
        "overlays": _overlays_snapshot(agent),
        "torrents": _torrents_snapshot(agent),
        "security": _security_snapshot(),
        "next_objective": _next_objective(agent),
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
            "bootstrap_cap_sats": manifest.admission.effective_bootstrap_cap_sats,
            "max_agents_per_seedbox": manifest.admission.max_agents_per_seedbox,
            "seedbox_cost_sats": manifest.admission.seedbox_cost_sats,
            "seedbox_growth_enabled": manifest.admission.seedbox_growth_enabled,
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


def _community_snapshot(agent: "OpenClawAgent") -> dict[str, Any] | None:
    """Read-only replay of this agent's signed community-log view."""
    manifest = agent.network_manifest
    if manifest is None:
        return None
    state = agent.community_state()
    if state is None:
        return None
    me = agent.community_reporter_id
    recent_entries = []
    for entry in sorted(
        agent.all_community_entries(),
        key=lambda item: (
            item.get("timestamp", ""),
            item.get("reporter_id", ""),
            item.get("entry_hash", ""),
        ),
    )[-10:]:
        details = entry.get("details") or {}
        recent_entries.append({
            "action": entry.get("action"),
            "reporter_id": entry.get("reporter_id"),
            "entry_hash": entry.get("entry_hash"),
            "amount_sats": details.get("amount_sats"),
            "cost_sats": details.get("cost_sats"),
            "purchase_intent_hash": details.get("purchase_intent_hash"),
            "seedbox_url": details.get("seedbox_url"),
        })
    return {
        "balance_sats": state.balance_sats,
        "member_count": state.member_count,
        "seedbox_count": state.seedbox_count,
        "pending_purchases": state.pending_purchases,
        "threshold_active": state.threshold_active(manifest),
        "my_membership_status": "admitted" if me in state.members else "outsider",
        "members": sorted(state.members),
        "recent_log_entries": recent_entries,
    }


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


_HANDLER_SUMMARY_MAX_CHARS = 240


def _overlays_snapshot(agent: "OpenClawAgent") -> list[dict[str, Any]]:
    """Per-overlay summary the LLM consumes inside the turn prompt.

    Field encodings ARE included so the LLM can call overlay_invoke
    without an extra tool round-trip. Handler text is truncated per
    message to keep the prompt bounded — the LLM can call
    ``overlay_describe`` for the full markdown when it needs it.

    Each entry carries an ``origin`` discriminator (``"markdown"`` or
    ``"python_class"``) so the LLM knows whether the absent
    ``handler_summary`` is "operator omitted it" or "no canonical text
    exists" for that overlay.
    """
    out: list[dict[str, Any]] = []
    for community_id in agent.registry.list_loaded():
        compiled = agent.registry._compiled[community_id]
        parsed = compiled.parsed
        if parsed is not None:
            name = parsed.identity.get("name", "")
            version = parsed.identity.get("version", "")
            messages = [
                {
                    "name": m.name,
                    "msg_id": m.msg_id,
                    "fields": [
                        {"name": f.name, "encoding": f.encoding}
                        for f in m.fields
                    ],
                    "handler_summary": _truncate(m.handler_text, _HANDLER_SUMMARY_MAX_CHARS),
                }
                for m in parsed.messages
            ]
        else:
            # Hand-written Community: synthesise the table from the
            # introspected payload classes the registry already populated.
            name = compiled.community_class.__name__
            version = ""
            messages = [
                {
                    "name": msg_name,
                    "msg_id": payload_cls.msg_id,
                    "fields": [
                        {"name": n, "encoding": fmt}
                        for n, fmt in zip(payload_cls.names, payload_cls.format_list)
                    ],
                    "handler_summary": "",
                }
                for msg_name, payload_cls in compiled.payload_classes.items()
            ]

        instance = agent.registry.get(community_id)
        out.append({
            "community_id_hex": community_id.hex(),
            "origin": compiled.origin,
            "name": name,
            "version": version,
            "messages": messages,
            "local_index": list(getattr(instance, "local_index", []))[:10],
            "response_cache": list(getattr(instance, "response_cache", []))[-10:],
        })
    return out


def _truncate(text: str, n: int) -> str:
    if len(text) <= n:
        return text
    return text[: n - 3] + "..."


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


def _next_objective(agent: "OpenClawAgent") -> dict[str, Any] | None:
    """Derive the most relevant unmet 7-step objective from the current snapshot.

    Pure rule table over read-only signals already present elsewhere in
    the snapshot (manifest admission policy, replayed community state,
    wallet address, torrent progress). Names objectives, not MCP tools,
    so the LLM still chooses how to act. Returns ``None`` when no
    objective applies — typically because the agent is done.

    When ``FILE_SHARE_MODE=1`` is set in the environment, the admission
    half of the rule table is skipped: non-gatekeeper agents jump
    straight to ``retrieve_content`` regardless of admission state, and
    the seedbox-growth step is suppressed entirely. Used by scenarios
    that demonstrate only the SEARCH/fetch path with no donation or
    treasury machinery.
    """
    manifest = agent.network_manifest
    if manifest is None:
        return {
            "label": "wait_for_manifest",
            "reason": "no network manifest is loaded yet; nothing to act on",
        }
    state = agent.community_state()
    if state is None:
        return {
            "label": "wait_for_manifest",
            "reason": "manifest is loaded but no community state has been replayed yet",
        }

    me = agent.community_reporter_id
    is_gatekeeper = agent.wallet.address() == manifest.admission.gatekeeper_address
    is_admitted = me in state.members
    treasury = state.balance_sats

    if os.environ.get("FILE_SHARE_MODE") == "1":
        has_completed_torrent = any(
            float(t.progress) >= 1.0 for t in agent.bittorrent.stats()
        )
        if is_gatekeeper or has_completed_torrent:
            return None
        return {
            "label": "retrieve_content (suggested tool: content_search_and_fetch)",
            "reason": (
                "file-share mode: admission/treasury machinery is "
                "disabled for this scenario; call content_search_and_fetch "
                "to fetch a Creative Commons file from a peer's library"
            ),
        }

    if not is_admitted:
        if treasury == 0 and is_gatekeeper:
            return {
                "label": "bootstrap_treasury (suggested tool: community_donate_and_join)",
                "reason": (
                    "you are the admission gatekeeper and the community "
                    "treasury is empty; a founding donation is required "
                    "before joiners can be admitted"
                ),
            }
        if treasury > 0:
            return {
                "label": "join_community (suggested tool: community_donate_and_join)",
                "reason": (
                    "you are not yet admitted; the treasury is funded so "
                    "a donation within the admission policy will admit you"
                ),
            }
        return {
            "label": "wait_for_founder",
            "reason": (
                "the community treasury is empty and you are not the "
                "gatekeeper; the founder must donate before joiners can be admitted"
            ),
        }

    if _pending_purchases_by(me, state) > 0:
        return {
            "label": "record_seedbox_provisioned (suggested tool: seedbox_provisioned)",
            "reason": (
                "one of your own seedbox_purchase_intent entries is still "
                "open; closing it with a provisioned event advances seedbox_count"
            ),
        }

    has_completed_torrent = any(
        float(t.progress) >= 1.0 for t in agent.bittorrent.stats()
    )
    if not is_gatekeeper and not has_completed_torrent:
        return {
            "label": "retrieve_content (suggested tool: content_search_and_fetch)",
            "reason": (
                "you are admitted but no local torrent has reached "
                "progress=1.0; the network exposes content overlays you "
                "can search and fetch from"
            ),
        }

    cost = manifest.admission.seedbox_cost_sats
    if (
        state.threshold_active(manifest)
        and treasury >= cost
        and state.pending_purchases == 0
    ):
        return {
            "label": "propose_seedbox_purchase (suggested tool: seedbox_purchase_propose)",
            "reason": (
                "member_count has grown past the current seedbox capacity, "
                "the treasury can cover seedbox_cost_sats, and no purchase "
                "intent is open"
            ),
        }

    return None


def _pending_purchases_by(reporter_id: str, state: Any) -> int:
    intents = {p.entry_hash for p in state.purchases if p.reporter_id == reporter_id}
    provisioned = {pv.purchase_intent_hash for pv in state.provisioned}
    return len(intents - provisioned)


def _security_snapshot() -> dict[str, Any] | None:
    path_raw = os.environ.get("SECURITY_EVIDENCE_PATH")
    if not path_raw:
        return None
    path = Path(path_raw)
    if not path.is_file():
        return {"ok": False, "layers": {}, "checklist": {}, "path": str(path)}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "ok": False,
            "layers": {},
            "checklist": {},
            "path": str(path),
            "error": f"{type(exc).__name__}: {exc}",
        }
    if isinstance(data, dict):
        data["path"] = str(path)
        return data
    return {
        "ok": False,
        "layers": {},
        "checklist": {},
        "path": str(path),
        "error": f"expected object, got {type(data).__name__}",
    }
