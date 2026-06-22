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
        "pending_overlay_offers": _pending_overlay_offers(agent),
        "authored_overlay_ids": _self_authored_overlay_ids(agent),
        "self_authored_announces_sent": _announce_sent_count(agent),
        "torrents": _torrents_snapshot(agent),
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
            "to_wallet": details.get("to_wallet"),
        })
    my_wallet = agent.wallet.address()
    balances = state.balances
    return {
        "balance_sats": state.balance_sats,
        "member_count": state.member_count,
        "my_membership_status": "admitted" if me in state.members else "outsider",
        "members": sorted(state.members),
        # Per-wallet net peer-to-peer transfer position (received − sent),
        # replayed from the signed log — the decentralized money ledger.
        "balances": balances,
        "my_wallet_address": my_wallet,
        "my_balance_sats": balances.get(my_wallet, 0),
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
        # Evolution provenance (parsed from the in-band # Identity block, or
        # empty for hand-written python_class overlays). Lets the LLM and the
        # trace renderer see authorship + lineage without a separate lookup.
        ident = parsed.identity if parsed is not None else {}
        out.append({
            "community_id_hex": community_id.hex(),
            "origin": compiled.origin,
            "name": name,
            "version": version,
            "messages": messages,
            "supersedes_hex": ident.get("supersedes") or None,
            "author_id": ident.get("author_id", ""),
            "change_summary": ident.get("change_summary", ""),
            "local_index": list(getattr(instance, "local_index", []))[:10],
            "response_cache": list(getattr(instance, "response_cache", []))[-10:],
            "received_announcements": list(getattr(instance, "received_announcements", []))[-10:],
        })
    return out


def _pending_overlay_offers(agent: "OpenClawAgent") -> list[dict[str, str]]:
    """OVERLAY_OFFERs received for overlays this agent does not yet run.

    Surfaced so an agent's LLM can decide whether to adopt a peer-authored
    overlay via ``overlay_fetch_and_load``. Empty when nothing is pending or
    the agent exposes no such accessor (older runtime).
    """
    fn = getattr(agent, "pending_overlay_offers", None)
    if fn is None:
        return []
    try:
        return list(fn())
    except Exception:
        return []


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


def _self_authored_overlay_ids(agent: "OpenClawAgent") -> list[str]:
    """community_ids this agent has authored, cross-process via the shared archive.

    The authoring tool runs in the MCP-service process; the watchdog snapshot
    runs in a separate process with a separate in-memory registry. So the
    in-memory registry is NOT a reliable "did I author" signal on the snapshot
    side. The per-demo overlay archive (a shared on-disk dir) IS — it records
    ``author_id`` + ``authored_ts`` for whatever the agent published, readable
    from either process. Falls back to the in-memory registry when no archive
    is configured (unit tests / ad-hoc single-process runs).
    """
    my_wallet = agent.wallet.address()
    archive = getattr(agent.registry, "_archive", None)
    if archive is not None:
        try:
            return archive.self_authored_ids(my_wallet)
        except Exception:
            pass
    out: list[str] = []
    for community_id in agent.registry.list_loaded():
        compiled = agent.registry._compiled.get(community_id)
        parsed = getattr(compiled, "parsed", None) if compiled else None
        if parsed is not None and parsed.identity.get("author_id") == my_wallet:
            out.append(community_id.hex())
    return out


def _should_author_overlay(agent: "OpenClawAgent") -> bool:
    """True iff this agent should be nudged to author a new overlay next.

    Two conditions, both required:

    * ``overlay_author_and_publish`` is in this agent's ``MCP_TOOL_ALLOWLIST``
      (per-agent env, written by scenario_boot and visible to the watchdog
      process). An ABSENT allowlist (legacy full-surface dev runs) returns
      False — we only nudge an agent explicitly granted the authoring tool, so
      the objective fires for fetcher_1 but not fetcher_2 / the seeder.
    * The agent has not already authored an overlay (per the shared archive).
      Once it has, the objective clears so the
      ``download_done_and_overlay_authored`` predicate can stop it — even
      though the authoring happened in the other process.
    """
    allowlist_raw = os.environ.get("MCP_TOOL_ALLOWLIST")
    if not allowlist_raw:
        return False
    allowed = {part.strip() for part in allowlist_raw.split(",") if part.strip()}
    if "overlay_author_and_publish" not in allowed:
        return False
    return not _self_authored_overlay_ids(agent)


def _base_overlay_for_evolution(agent: "OpenClawAgent") -> tuple[str, str] | None:
    """Return ``(name, cid_hex)`` for the peer-authored overlay this agent
    should succeed in v1.1, or ``None``.

    The scenario sets ``EVOLUTION_BASE_OVERLAY_NAME`` (e.g.
    ``download_announce`` for file_share) at boot. We look that name up in a
    spec the agent HOLDS (adopted or authored) and return the cid the LLM
    should pass as ``supersedes_cid_hex``. Specs this agent authored itself
    are skipped — that would be re-authoring v1.0.0, not succeeding it.

    Cross-process bridge: the MCP-side OpenClawAgent loads adopted overlays
    into a registry inside ITS OWN process. The watchdog snapshot agent that
    runs this rule lives in a SEPARATE process and has its own (empty)
    registry. The shared structure both processes see is the on-disk overlay
    archive (``OVERLAY_ARCHIVE_DIR``), where every load writes a meta.json
    carrying ``name`` and ``author_id``. We read the archive first so the
    snapshot reflects the MCP's actual adoptions, and fall back to the local
    registry for unit-test paths that don't configure an archive dir.
    """
    name_env = os.environ.get("EVOLUTION_BASE_OVERLAY_NAME", "").strip()
    if not name_env:
        return None
    my_wallet = agent.wallet.address()

    archive_env = os.environ.get("OVERLAY_ARCHIVE_DIR")
    if archive_env:
        archive_dir = Path(archive_env)
        if archive_dir.is_dir():
            for meta_path in sorted(archive_dir.glob("*.meta.json")):
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if meta.get("name") != name_env:
                    continue
                if meta.get("author_id") == my_wallet:
                    continue
                cid_hex = meta.get("community_id_hex")
                if cid_hex:
                    return name_env, cid_hex

    for community_id in agent.registry.list_loaded():
        compiled = agent.registry._compiled.get(community_id)
        parsed = getattr(compiled, "parsed", None) if compiled else None
        if parsed is None:
            continue
        if parsed.identity.get("name") != name_env:
            continue
        if parsed.identity.get("author_id") == my_wallet:
            continue
        return name_env, community_id.hex()
    return None


def _announce_sent_counter_path(agent: "OpenClawAgent") -> Path:
    """Path of the shared on-disk counter the announce tool flips.

    Lives in ``save_dir`` alongside the BT download ledger / offers file so
    both the MCP-service process (which sends the ANNOUNCE) and the watchdog
    snapshot process (which reads it in ``_announce_sent_count``) see the same
    value. Same cross-process bridge pattern the v3.x bridges use.
    """
    return Path(agent.bittorrent.save_dir) / ".self_authored_announces_sent.jsonl"


def _announce_sent_count(agent: "OpenClawAgent") -> int:
    """Number of ANNOUNCEs this agent has sent on a self-authored overlay.

    Cross-process visible: the ``overlay_invoke`` tool, when called on an
    overlay whose ``author_id`` matches the agent's wallet, appends one line
    to the counter file. The watchdog snapshot reads the file (empty if no
    sends yet) so its ``announce_pending`` rule can clear.
    """
    path = _announce_sent_counter_path(agent)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    return sum(1 for line in text.splitlines() if line.strip())


def _consecutive_compile_fails_for_name(agent: "OpenClawAgent", name: str) -> int:
    """Number of ``compile_fail`` events on the agent's ledger since the most
    recent ``authored`` event for ``name`` (or since the start if none).

    The watchdog uses this to cap retries on ``author_overlay_v_next`` when
    Haiku spirals on a single design (e.g. consistently picking bytes20 and
    providing hex-string samples — the documented zero-shot encoding boundary).
    Without this cap a stuck agent would re-attempt every 240s for the full
    wall clock, burning LLM quota with no chance of success.

    ``compile_fail`` records do not carry ``name`` (the helper that writes them
    only knows the cid at failure time), so this counts ALL compile_fails since
    the last authored event for ``name`` — a small over-cap in the unlikely
    case multiple overlays fail in parallel, harmless in practice.
    """
    if not name:
        return 0
    archive = getattr(agent.registry, "_archive", None)
    if archive is None:
        return 0
    ledger_path = archive.ledger_path
    try:
        text = ledger_path.read_text(encoding="utf-8")
    except OSError:
        return 0
    count = 0
    for raw in reversed(text.splitlines()):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        event = rec.get("event")
        if event == "authored" and rec.get("name") == name:
            break
        if event == "compile_fail":
            count += 1
    return count


def _evolution_peer_mid(agent: "OpenClawAgent") -> str | None:
    """``mid_hex`` of the single non-genesis peer to ANNOUNCE to, or None.

    In file_share the genesis author (fetcher_1) must UNICAST its ANNOUNCE to
    the successor (fetcher_2) so the latter can observe the protocol in use.
    ``overlay_invoke`` is point-to-point, so we need a concrete target mid.

    file_share disables admission, so PEER_INTRO never runs and peer wallet
    metadata is empty — we cannot match the successor by wallet. Instead we
    treat the manifest's genesis peer(s) (the seeder) as infrastructure and
    return the one known peer that is NOT a genesis peer. With the fetchers
    meshed, that is unambiguously the other fetcher.

    Returns None when the manifest is missing, no peers are known yet, or the
    non-genesis peer can't be uniquely identified — the announce objective
    then waits for a later tick rather than guessing.
    """
    manifest = agent.network_manifest
    if manifest is None:
        return None
    from ipv8.keyvault.crypto import default_eccrypto
    from ipv8.peer import Peer

    genesis_mids: set[bytes] = set()
    for gp in manifest.genesis_peers:
        try:
            pub = default_eccrypto.key_from_public_bin(bytes.fromhex(gp.pubkey_hex))
        except Exception:
            continue
        genesis_mids.add(Peer(pub).mid)

    # Dedup by mid (a peer's MCP and watchdog ports share one identity).
    candidates = [p.mid for p in agent.known_peers() if p.mid not in genesis_mids]
    uniq = list(dict.fromkeys(candidates))
    if len(uniq) == 1:
        return uniq[0].hex()
    return None


def _authoring_objective(agent: "OpenClawAgent") -> dict[str, Any] | None:
    """The shared overlay author/adopt/announce/evolve ladder.

    Used by both the file_share retrieval chain and the payment demo once the
    triggering phase-1 task (download / receiving a payment) is done. Names
    objectives, not tools (the LLM still chooses), but NAMES the tool because
    Haiku narrates intent without picking the tool from prose alone (see
    project_zeroshot_finding). Cross-process safe: reads the on-disk overlay
    archive, not the MCP-process registry.
    """
    author_mode = os.environ.get("OVERLAY_AUTHOR_MODE", "").strip()
    if _should_author_overlay(agent):
        base = _base_overlay_for_evolution(agent)
        # A peer-authored base overlay is HELD (adopted into this agent's
        # archive) → DESIGN a successor (v1.1.0). The trigger is adoption
        # (cross-process via the overlay archive), not observed traffic.
        if base is not None:
            base_name, base_cid_hex = base
            # Defensive cap: stop nudging after N consecutive compile_fails so a
            # zero-shot encoding spiral doesn't burn quota each tick.
            fail_streak = _consecutive_compile_fails_for_name(agent, base_name)
            if fail_streak >= 3:
                return {
                    "label": "stuck_in_zero_shot_failure",
                    "reason": (
                        f"this agent has produced {fail_streak} consecutive "
                        f"compile_fail events authoring {base_name!r} without "
                        f"a successful spec. The LLM is stuck on a design "
                        f"detail the structural validator keeps rejecting "
                        f"(typically a bytes-encoding mismatch). Stopping "
                        f"author retries; the failures are recorded in the "
                        f"overlay ledger as data for the writeup."
                    ),
                    "base_overlay_cid_hex": base_cid_hex,
                    "consecutive_compile_fails": fail_streak,
                }
            return {
                "label": "author_overlay_v_next (suggested tool: overlay_author_and_publish)",
                "reason": (
                    f"you have ADOPTED the peer-authored overlay "
                    f"{base_name!r} (cid={base_cid_hex[:12]}); now DESIGN "
                    f"a successor protocol that improves it. Add ONE field "
                    f"that would help peers (you decide what). Call "
                    f"overlay_author_and_publish with "
                    f"supersedes_cid_hex={base_cid_hex!r}; see your mission's "
                    f"Phase 2 for the structural rules."
                ),
                "base_overlay_cid_hex": base_cid_hex,
            }
        if author_mode == "successor":
            # A successor NEVER authors v1.0.0 from scratch. It must first
            # ADOPT the genesis author's base overlay (cross-process archive).
            offers = agent.pending_overlay_offers()
            if offers:
                offer = offers[0]
                return {
                    "label": "adopt_overlay (suggested tool: overlay_fetch_and_load)",
                    "reason": (
                        "a peer offered you a new overlay protocol. Adopt "
                        "it so you can design a successor — do NOT author "
                        "your own version. Call overlay_fetch_and_load with "
                        f"peer_mid={offer['from_peer_mid']!r} and "
                        f"md_hash_hex={offer['md_hash_hex']!r}."
                    ),
                    "offer_peer_mid": offer["from_peer_mid"],
                    "offer_md_hash_hex": offer["md_hash_hex"],
                }
            # No offer yet — wait for the genesis author to publish.
            return None
        # genesis / legacy: author the first version prescriptively. The exact
        # spec (name, message, fields) lives in the agent's mission Phase 2.
        return {
            "label": "author_overlay (suggested tool: overlay_author_and_publish)",
            "reason": (
                "your phase-1 task is done; now publish the new overlay "
                "protocol your mission describes so peers can adopt it. "
                "Call overlay_author_and_publish with the exact arguments "
                "in your mission's Phase 2."
            ),
        }
    # Branch B: the genesis author HAS published its overlay. If it hasn't yet
    # sent a message on it, send ONE so the successor observes the protocol in
    # use. A ``successor`` is excluded (it stops once it authored v1.1.0). The
    # exact message name + fields live in the agent's mission Phase 3.
    if (
        author_mode != "successor"
        and _self_authored_overlay_ids(agent)
        and _announce_sent_count(agent) == 0
    ):
        authored = _self_authored_overlay_ids(agent)[0]
        target_mid = _evolution_peer_mid(agent)
        if target_mid is None:
            # No distinct observer peer resolvable yet — wait for the mesh.
            return None
        return {
            "label": "announce_pending (suggested tool: overlay_invoke)",
            "reason": (
                f"you authored an overlay (cid={authored[:12]}) but have not "
                f"yet sent a message on it. Send ONE message to the peer "
                f"that needs to observe your protocol. Call overlay_invoke "
                f"with community_id_hex={authored!r}, peer_mid={target_mid!r}, "
                f"and the message name + fields your mission's Phase 3 "
                f"specifies. One call, then stop."
            ),
            "authored_overlay_cid_hex": authored,
            "announce_target_mid": target_mid,
        }
    return None


def _payment_objective(
    agent: "OpenClawAgent", state: Any, me: str, is_gatekeeper: bool,
) -> dict[str, Any] | None:
    """Objective ladder for an admitted agent in the payment demo.

    Founder/payer (gatekeeper): pay each admitted joiner once (the joiner's
    replayed balance is still 0). Joiner: request a payment until paid, then
    hand off to the shared authoring ladder. All signals come from replayed
    signed-log state + PEER_INTRO metadata — cross-process safe.
    """
    my_wallet = agent.wallet.address()
    balances = state.balances
    member_wallets = set(state.member_wallets.values())

    if is_gatekeeper:
        peer_meta = agent.seedbox.peer_meta if agent.seedbox else {}
        for peer in agent.known_peers():
            meta = peer_meta.get(peer.mid)
            wallet = getattr(meta, "wallet_address", "") if meta else ""
            if not wallet or wallet == my_wallet:
                continue
            if wallet not in member_wallets:
                continue  # not an admitted member yet
            if balances.get(wallet, 0) != 0:
                continue  # already paid this member
            return {
                "label": "pay_member (suggested tool: send_payment)",
                "reason": (
                    "you are the founder; an admitted member has joined and "
                    "asked for funds. Send them the amount your mission "
                    f"specifies. Call send_payment with to_peer_mid={peer.mid.hex()!r}."
                ),
                "pay_target_mid": peer.mid.hex(),
                "pay_target_wallet": wallet,
            }
        return None  # everyone paid; keep running (founder stop is 'never')

    # Joiner: ask for funds until paid, then move to the authoring chain.
    if balances.get(my_wallet, 0) <= 0:
        return {
            "label": "request_payment (suggested tool: request_payment)",
            "reason": (
                "you are admitted but have not yet been paid. Ask the "
                "community for fake BTC: call request_payment with the "
                "amount your mission specifies."
            ),
        }
    # Got paid → proceed to the overlay authoring / evolution chain.
    return _authoring_objective(agent)


def _next_objective(agent: "OpenClawAgent") -> dict[str, Any] | None:
    """Derive the most relevant unmet objective from the current snapshot.

    Pure rule table over read-only signals already present elsewhere in
    the snapshot (manifest admission policy, replayed community state,
    wallet address, torrent progress). Names objectives, not MCP tools,
    so the LLM still chooses how to act. Returns ``None`` when no
    objective applies — typically because the agent is done.

    When ``FILE_SHARE_MODE=1`` is set in the environment, the admission
    half of the rule table is skipped: non-gatekeeper agents jump
    straight to ``retrieve_content`` regardless of admission state. Used
    by scenarios that demonstrate only the SEARCH/fetch path with no
    donation or treasury machinery.
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
        if not is_gatekeeper and not has_completed_torrent:
            return {
                "label": "retrieve_content (suggested tool: content_search_and_fetch)",
                "reason": (
                    "file-share mode: admission/treasury machinery is "
                    "disabled for this scenario; call content_search_and_fetch "
                    "to fetch a Creative Commons file from a peer's library"
                ),
            }
        # Download done (or we're the gatekeeper). Hand off to the shared
        # author/adopt/announce ladder.
        return _authoring_objective(agent)

    if os.environ.get("PAYMENT_MODE") == "1" and is_admitted:
        return _payment_objective(agent, state, me, is_gatekeeper)

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

    return None
