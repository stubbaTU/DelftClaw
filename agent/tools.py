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
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from ipv8.peer import Peer

from agent.runtime import OpenClawAgent
from communication.community import overlay_id


# Tool-dispatch logger — one line per LLM tool invocation, paired with
# the IPv8 wire log from ``communication.community._log_wire``. Surfaces
# in ``journalctl`` (basicConfig wired in ``agent/cli.py``). Grep:
#   make watch NAME=… | grep TOOL
_tool_logger = logging.getLogger("delftclaw.agent.tools")


def _short(value: Any, n: int = 80) -> str:
    """Render a tool arg/result compactly for a single log line."""
    try:
        s = json.dumps(value, default=str)
    except (TypeError, ValueError):
        s = str(value)
    return s if len(s) <= n else (s[: n - 1] + "…")


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
        t0 = time.monotonic()
        _tool_logger.info("TOOL call name=%s args=%s", name, _short(args))
        if name not in self._tools:
            _tool_logger.warning("TOOL miss name=%s (unknown)", name)
            return {"error": f"unknown_tool:{name}"}
        try:
            result = await self._tools[name].fn(**args)
            _tool_logger.info(
                "TOOL ok   name=%s elapsed=%.3fs result=%s",
                name, time.monotonic() - t0, _short(result),
            )
            return result
        except Exception as exc:
            _tool_logger.warning(
                "TOOL fail name=%s elapsed=%.3fs error=%s: %s",
                name, time.monotonic() - t0, type(exc).__name__, exc,
            )
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
        try:
            peer = agent.add_peer(host, port, pubkey_hex)
        except (ValueError, TypeError) as exc:
            return {"error": f"invalid_pubkey_hex: {exc}"}
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

    # ---- Community treasury + signed-log layer (Phase 4) --------------

    def _community_summary() -> dict[str, Any]:
        """Internal: snapshot of {balance, member_count, threshold_status,
        my_membership_status, seedbox_count} computed from the local
        signed log + peer-log union.

        Returns an empty dict when no manifest is loaded; callers should
        guard against that.
        """
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

    async def community_log_list_recent(limit: int = 50) -> list[dict[str, Any]]:
        """Return the most-recent entries from the merged community log.

        Merges this agent's own signed log with every peer's cached chain
        (deterministic order by ``(timestamp, reporter_id, entry_hash)``),
        filtered to community actions. Each returned dict carries
        ``action``, ``reporter_id``, ``timestamp``, ``entry_hash``, the
        relevant ``details`` fields, and an ``accepted`` flag computed by
        replay validation. Returns at most ``limit`` entries (most-recent
        last).
        """
        from agent.community_state import (
            COMMUNITY_ACTIONS,
            replay_community,
        )

        manifest = agent.network_manifest
        if manifest is None:
            return []
        all_entries = agent.all_community_entries()
        relevant = [e for e in all_entries if e.get("action") in COMMUNITY_ACTIONS]
        ordered = sorted(
            relevant,
            key=lambda e: (
                e.get("timestamp", ""),
                e.get("reporter_id", ""),
                e.get("entry_hash", ""),
            ),
        )
        # Determine accepted-vs-rejected by re-running replay and matching
        # entry_hash sets. Cheap because replay is pure.
        state = replay_community(manifest, ordered)
        accepted_hashes = (
            {d.entry_hash for d in state.donations}
            | {p.entry_hash for p in state.purchases}
            | {v.entry_hash for v in state.provisioned}
        )
        out: list[dict[str, Any]] = []
        for entry in ordered[-max(0, int(limit)):]:
            details = entry.get("details") or {}
            out.append({
                "action": entry.get("action"),
                "reporter_id": entry.get("reporter_id"),
                "timestamp": entry.get("timestamp"),
                "entry_hash": entry.get("entry_hash"),
                "amount_sats": details.get("amount_sats"),
                "cost_sats": details.get("cost_sats"),
                "purchase_intent_hash": details.get("purchase_intent_hash"),
                "seedbox_url": details.get("seedbox_url"),
                "accepted": entry.get("entry_hash") in accepted_hashes,
            })
        return out

    async def community_treasury_balance() -> dict[str, Any]:
        """Current treasury balance + member count + threshold status.

        Returns ``{"error": "no_manifest_loaded"}`` if the agent hasn't
        injected a network manifest yet.
        """
        summary = _community_summary()
        if not summary:
            return {"error": "no_manifest_loaded"}
        return summary

    async def community_member_count() -> dict[str, Any]:
        """Current admitted-member count. Returns my own membership status too."""
        summary = _community_summary()
        if not summary:
            return {"error": "no_manifest_loaded"}
        return {
            "member_count": summary["member_count"],
            "my_membership_status": summary["my_membership_status"],
            "threshold_active": summary["threshold_active"],
        }

    async def community_donate_and_join(amount_sats: int) -> dict[str, Any]:
        """Compose a signed ``donation_intent`` entry and append it to our log.

        The amount is debited from this agent's synthetic wallet (so
        ``wallet_balance`` reflects the spend) before the entry is
        signed. The entry will propagate to peers via the redteam pull
        loop (Phase 6); peers' replay will accept it iff the donation
        rules in ``community_state.replay_community`` are met:

          - amount >= manifest.admission.min_sats
          - amount <= bootstrap_cap_sats (donor #1) or <= running average
          - we are not already an admitted member

        Returns the produced entry's ``entry_hash`` + a summary, or an
        ``error`` field on local validation failure.
        """
        manifest = agent.network_manifest
        if manifest is None:
            return {"error": "no_manifest_loaded"}
        if not isinstance(amount_sats, int) or amount_sats < 1:
            return {"error": f"amount_sats must be a positive int; got {amount_sats!r}"}

        # Local sanity pass: refuse to write entries the replay layer
        # would reject anyway. Strictly an optimisation — the wire-side
        # validator is authoritative.
        state = agent.community_state()
        me = agent.community_reporter_id
        if state is not None and me in state.members:
            return {"error": "already_admitted"}
        if amount_sats < manifest.admission.min_sats:
            return {"error": f"amount below min_sats {manifest.admission.min_sats}"}
        if state is None or not state.donations:
            cap = manifest.admission.effective_bootstrap_cap_sats
        else:
            avg = sum(d.amount_sats for d in state.donations) // len(state.donations)
            cap = max(manifest.admission.min_sats, avg)
        if amount_sats > cap:
            return {"error": f"amount above cap {cap}"}

        # Debit the synthetic wallet so wallet_balance + treasury stay in
        # sync. Raises ValueError("insufficient funds") if the wallet
        # was constructed with a tracked balance that can't cover it.
        try:
            agent.wallet.send(manifest.admission.gatekeeper_address, amount_sats)
        except ValueError as exc:
            return {"error": f"wallet_send_failed: {exc}"}

        entry = agent.community_log.append_event(
            reporter_id=me,
            subject_id=me,
            action="donation_intent",
            details={
                "network_id_hex": manifest.network_id.hex(),
                "amount_sats": amount_sats,
            },
        )
        return {
            "entry_hash": entry["entry_hash"],
            "amount_sats": amount_sats,
            "network_id_hex": manifest.network_id.hex(),
        }

    async def community_join_via_peer(
        gatekeeper_mid: str, amount_sats: int, timeout_s: float = 30.0,
    ) -> dict[str, Any]:
        """Sign + append + ship a donation_intent to ``gatekeeper_mid``.

        End-to-end Phase 5 admission path:

          1. ``community_donate_and_join(amount_sats)`` writes the signed
             entry to our local community log (debits wallet, runs
             local pre-checks).
          2. Find the peer by mid prefix, then send the entry over the
             new ``COMMUNITY_JOIN_REQUEST`` wire message.
          3. Wait for the gatekeeper's accept/reject response. The
             gatekeeper validates the entry against its own
             community-state replay.

        Returns ``{"entry_hash": str, "accepted": bool, "reason": str,
        "amount_sats": int}`` on success, or ``{"error": str}`` on
        local pre-check failure.
        """
        # Step 1 — sign + append locally. Reuses the pre-existing tool
        # so wallet debit, double-join check, cap check, etc. all run.
        donate_result = await community_donate_and_join(amount_sats)
        if "error" in donate_result:
            return donate_result

        # Step 2 — locate the entry we just wrote so we can ship it.
        entries = agent.community_log.read_entries()
        signed_entry = next(
            (e for e in reversed(entries) if e.get("entry_hash") == donate_result["entry_hash"]),
            None,
        )
        if signed_entry is None:
            return {"error": "signed_entry_not_found_in_local_log"}

        # Step 3 — find the peer and send.
        try:
            peer = _resolve_peer(agent, gatekeeper_mid)
        except KeyError as exc:
            return {"error": f"peer_not_found:{exc}"}
        future = agent.seedbox.request_community_join(peer, signed_entry)
        try:
            accepted, reason = await asyncio.wait_for(future, timeout=timeout_s)
        except asyncio.TimeoutError:
            return {"error": f"community_join_timeout_after_{timeout_s}s"}

        return {
            "entry_hash": donate_result["entry_hash"],
            "amount_sats": amount_sats,
            "accepted": accepted,
            "reason": reason,
        }

    async def seedbox_purchase_propose(cost_sats: int | None = None) -> dict[str, Any]:
        """Sign + append a ``seedbox_purchase_intent`` entry to our log.

        First-comer wins: the intent is only accepted by replay if no
        prior pending purchase exists. ``cost_sats`` defaults to the
        manifest's ``seedbox_cost_sats`` (the manifest is the source of
        truth — passing a different value just causes the entry to be
        rejected at replay).

        Local sanity check refuses the write if the threshold isn't
        tripped or the treasury can't cover the cost; this is an
        optimisation — the replay validator is authoritative.
        """
        manifest = agent.network_manifest
        if manifest is None:
            return {"error": "no_manifest_loaded"}
        if not manifest.admission.seedbox_growth_enabled:
            return {"error": "growth_disabled_in_manifest"}

        state = agent.community_state()
        if state is None:
            return {"error": "no_manifest_loaded"}

        me = agent.community_reporter_id
        if me not in state.members:
            return {"error": "not_admitted"}

        cost = cost_sats if cost_sats is not None else manifest.admission.seedbox_cost_sats
        if not isinstance(cost, int) or cost < 1:
            return {"error": f"cost_sats must be a positive int; got {cost!r}"}
        if cost != manifest.admission.seedbox_cost_sats:
            return {"error": f"cost {cost} != manifest.seedbox_cost_sats "
                             f"{manifest.admission.seedbox_cost_sats}"}
        if state.balance_sats < cost:
            return {"error": f"insufficient treasury: balance={state.balance_sats}, cost={cost}"}
        if not state.threshold_active(manifest):
            return {"error": "threshold_not_active"}
        if state.pending_purchases != 0:
            return {"error": "pending_purchase_already_in_flight"}

        entry = agent.community_log.append_event(
            reporter_id=me,
            subject_id=me,
            action="seedbox_purchase_intent",
            details={
                "network_id_hex": manifest.network_id.hex(),
                "cost_sats": cost,
            },
        )
        return {
            "entry_hash": entry["entry_hash"],
            "cost_sats": cost,
            "network_id_hex": manifest.network_id.hex(),
        }

    async def seedbox_provisioned(
        purchase_intent_hash: str,
        seedbox_url: str,
        seedbox_pubkey_hex: str,
    ) -> dict[str, Any]:
        """Sign + append a ``seedbox_provisioned`` entry closing a purchase intent.

        Phase-8 demo path: the actual VPS spawn is mocked — writing this
        entry IS the provisioning event from the community's point of
        view. Whichever member won the first-comer purchase intent
        announces here that the new seedbox is up; community-state
        replay validates the close (signer is admitted, intent exists,
        intent not already closed) and bumps ``seedbox_count``.

        Real cloud-spawn (sporestack / hostinger / etc.) goes in
        ``replication/`` and is wired to this tool in a later phase.

        Local pre-checks refuse to write if no pending intent matches
        the supplied ``purchase_intent_hash`` — the replay layer would
        drop it anyway. ``seedbox_url`` is a free-form locator (e.g.
        ``mock-seedbox-2.delftclaw.test:18769`` for the demo);
        ``seedbox_pubkey_hex`` is the new seedbox's IPv8 pubkey hex.
        """
        manifest = agent.network_manifest
        if manifest is None:
            return {"error": "no_manifest_loaded"}

        state = agent.community_state()
        if state is None:
            return {"error": "no_manifest_loaded"}

        me = agent.community_reporter_id
        if me not in state.members:
            return {"error": "not_admitted"}

        if not isinstance(purchase_intent_hash, str) or not purchase_intent_hash:
            return {"error": "purchase_intent_hash required"}
        if not isinstance(seedbox_url, str) or not seedbox_url:
            return {"error": "seedbox_url required"}
        if not isinstance(seedbox_pubkey_hex, str) or not seedbox_pubkey_hex:
            return {"error": "seedbox_pubkey_hex required"}

        matching = next(
            (p for p in state.purchases if p.entry_hash == purchase_intent_hash),
            None,
        )
        if matching is None:
            return {"error": f"no_matching_purchase_intent:{purchase_intent_hash[:16]}"}

        already_closed = any(
            v.purchase_intent_hash == purchase_intent_hash for v in state.provisioned
        )
        if already_closed:
            return {"error": "purchase_intent_already_closed"}

        entry = agent.community_log.append_event(
            reporter_id=me,
            subject_id=me,
            action="seedbox_provisioned",
            details={
                "network_id_hex": manifest.network_id.hex(),
                "purchase_intent_hash": purchase_intent_hash,
                "seedbox_url": seedbox_url,
                "seedbox_pubkey_hex": seedbox_pubkey_hex,
            },
        )
        return {
            "entry_hash": entry["entry_hash"],
            "purchase_intent_hash": purchase_intent_hash,
            "seedbox_url": seedbox_url,
            "seedbox_pubkey_hex": seedbox_pubkey_hex,
            "network_id_hex": manifest.network_id.hex(),
        }

    # ---- Overlays ------------------------------------------------------

    async def overlays_list() -> list[dict[str, Any]]:
        """Full per-overlay spec the LLM needs to invoke any message zero-shot.

        Each entry carries an ``origin`` discriminator:
          - ``"markdown"`` — the v5.1 path; identity / messages / errors
            / dependencies all populated from the parsed descriptor.
          - ``"python_class"`` — hand-written Community registered via
            ``OverlayRegistry.register_community(cls)``; prose-only
            fields (description, handler_text, errors, dependencies)
            are empty but message structural metadata (msg_id, field
            encodings) is present so ``overlay_invoke`` still works.
        """
        from protocol.registry import overlay_to_dict
        return [
            overlay_to_dict(agent.registry._compiled[cid])
            for cid in agent.registry.list_loaded()
        ]

    OVERLAY_DESCRIBE_MAX_BYTES = 32 * 1024

    async def overlay_describe(community_id_hex: str) -> dict[str, Any]:
        """Return the canonical markdown of a loaded overlay (truncated if oversized).

        Returns ``{"error": "no_canonical_md:python_class"}`` for
        overlays registered via ``register_community(cls)`` — there is
        no canonical text for a hand-written Python class.
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

    async def overlay_fetch_and_load(peer_mid: str, md_hash_hex: str) -> dict[str, Any]:
        peer = _resolve_peer(agent, peer_mid)
        md_hash = bytes.fromhex(md_hash_hex)
        future = agent.seedbox.fetch_overlay(peer, md_hash)
        md_bytes = await asyncio.wait_for(future, timeout=10)
        # ``aload`` runs the (potentially multi-second) compile via
        # asyncio.to_thread so the IPv8 event loop keeps servicing
        # packets while the LLM call is in flight.
        instance = await agent.registry.aload(md_bytes.decode("utf-8"))
        return {
            "community_id_hex": instance.community_id.hex(),
            "loaded": True,
        }

    async def overlay_publish(md_text: str) -> str:
        md_hash = agent.seedbox.publish_overlay(md_text)
        # Also load it locally so we serve traffic on the new overlay.
        await agent.registry.aload(md_text)
        return md_hash.hex()

    # ---- Network manifest -----------------------------------------------

    async def agent_inject_manifest(md_text: str) -> dict[str, Any]:
        """Parse + cache a network manifest into this agent's runtime.

        Pre-introduces every genesis peer (skipping self). Idempotent on
        ``network_id``. Used by ``scenario_boot`` to hand a freshly-
        generated manifest to a joining agent, and by the LLM after a
        MANIFEST_DELIVERY round-trip.

        Short-circuit guard: when the agent ALREADY has a manifest
        loaded (the common case — scenario_boot pre-injects it at
        boot), return ``{"already_loaded": True, …}`` without parsing
        the caller's ``md_text``. Driven by an LLM bug we caught
        in 20:34:30+: Haiku was inventing manifest markdown and
        calling this tool every turn instead of donating. The
        synthesised markdown didn't pass the schema parser, so the
        LLM never advanced. With the short-circuit it sees
        ``already_loaded`` and pivots to a real action
        (community_donate_and_join etc.).
        """
        from protocol.manifest import ManifestParseError

        if agent.network_manifest is not None:
            return {
                "already_loaded": True,
                "network_id_hex": agent.network_manifest.network_id.hex(),
                "name": agent.network_manifest.identity.get("name", ""),
                "genesis_peers": len(agent.network_manifest.genesis_peers),
                "default_overlays": list(agent.network_manifest.default_overlays),
                "note": (
                    "Manifest is already loaded — its contents are in "
                    "state.network. You do NOT need to inject it again. "
                    "If you're trying to JOIN this network, call "
                    "community_join_via_peer or community_donate_and_join "
                    "with the policy from state.network.admission."
                ),
            }

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

        Tool("community_log_list_recent",
             "Return the most-recent merged community-log entries "
             "(donation_intent, seedbox_purchase_intent, "
             "seedbox_provisioned) across this agent's chain and every "
             "known peer's chain, with an ``accepted`` flag per entry.",
             {"type": "object",
              "properties": {
                  "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
              },
              "additionalProperties": False},
             community_log_list_recent),

        Tool("community_treasury_balance",
             "Snapshot of the community's no-treasurer treasury: "
             "balance_sats (sum of accepted donations minus accepted "
             "purchases), member_count, seedbox_count, threshold_active, "
             "pending_purchases, and our own membership status.",
             P_NONE, community_treasury_balance),

        Tool("community_member_count",
             "Number of admitted members + our own membership status + "
             "whether the seedbox-growth threshold is tripped.",
             P_NONE, community_member_count),

        Tool("community_donate_and_join",
             "Compose a signed donation_intent entry for ``amount_sats`` "
             "and append it to our community log. Replay-validation rules "
             "(min_sats, bootstrap_cap, running-average cap, no double-join) "
             "are pre-checked locally; on success the entry propagates to "
             "peers and admits us when they replay.",
             {"type": "object",
              "properties": {
                  "amount_sats": {"type": "integer", "minimum": 1,
                                  "description": "satoshis to donate; must be in "
                                                 "[min_sats, running_avg_cap]"},
              },
              "required": ["amount_sats"],
              "additionalProperties": False},
             community_donate_and_join),

        Tool("seedbox_purchase_propose",
             "Sign + append a seedbox_purchase_intent entry. First-comer "
             "wins on race; replay rejects intents when threshold is not "
             "tripped or treasury can't cover the cost. ``cost_sats`` "
             "defaults to the manifest's declared price.",
             {"type": "object",
              "properties": {
                  "cost_sats": {"type": "integer", "minimum": 1,
                                "description": "satoshis to spend; must match "
                                               "manifest.seedbox_cost_sats exactly"},
              },
              "additionalProperties": False},
             seedbox_purchase_propose),

        Tool("seedbox_provisioned",
             "Close a pending seedbox_purchase_intent by signing + "
             "appending a seedbox_provisioned entry. Phase-8 mock "
             "provisioning: writing this entry is the community-visible "
             "act of spawning a new seedbox. Replay bumps seedbox_count "
             "by 1 on accept. Use after the cloud-spawn / mock-spawn "
             "succeeds.",
             {"type": "object",
              "properties": {
                  "purchase_intent_hash": {
                      "type": "string",
                      "description": "entry_hash of the seedbox_purchase_intent "
                                     "this provision event closes",
                  },
                  "seedbox_url": {
                      "type": "string",
                      "description": "reachable address of the new seedbox "
                                     "(e.g. 'mock-seedbox-2.delftclaw.test:18769')",
                  },
                  "seedbox_pubkey_hex": {
                      "type": "string",
                      "description": "the new seedbox's IPv8 pubkey hex "
                                     "(for future SEARCH-response identity binding)",
                  },
              },
              "required": ["purchase_intent_hash", "seedbox_url", "seedbox_pubkey_hex"],
              "additionalProperties": False},
             seedbox_provisioned),

        Tool("community_join_via_peer",
             "Phase-5 end-to-end admission: write a signed donation_intent "
             "to our local community log, ship it to the gatekeeper peer "
             "over COMMUNITY_JOIN_REQUEST, and await the accept/reject "
             "response. Use this once an admitted peer is reachable "
             "(via peer_add or the network manifest's genesis peers).",
             {"type": "object",
              "properties": {
                  "gatekeeper_mid": {"type": "string",
                                     "description": "hex prefix of the gatekeeper's IPv8 mid"},
                  "amount_sats": {"type": "integer", "minimum": 1},
                  "timeout_s": {"type": "number", "default": 30.0},
              },
              "required": ["gatekeeper_mid", "amount_sats"],
              "additionalProperties": False},
             community_join_via_peer),

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
