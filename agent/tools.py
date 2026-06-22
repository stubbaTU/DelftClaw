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


# Tool-dispatch logger — one line per LLM tool invocation, paired with
# the IPv8 wire log from ``communication.community._log_wire``. Surfaces
# in ``journalctl`` (basicConfig wired in ``agent/cli.py``). Grep:
#   make watch NAME=… | grep TOOL
_tool_logger = logging.getLogger("delftclaw.agent.tools")
_wire_logger = logging.getLogger("delftclaw.communication.wire")


def _maybe_record_self_authored_announce(
    agent: "OpenClawAgent",
    community_id: bytes,
    message_name: str,
) -> None:
    """If the message is sent on a SELF-AUTHORED overlay, record it cross-process.

    The deploy.state_snapshot.``announce_pending`` next_objective rule reads
    ``<save_dir>/.self_authored_announces_sent.jsonl`` to know whether the
    agent has sent at least one message on its own protocol — same shared-disk
    bridge pattern the BT download ledger and overlay offers use, because the
    MCP-service process sends while the watchdog snapshot process reads. A
    failed write is silent: this is observability, not correctness.
    """
    compiled = agent.registry._compiled.get(community_id)
    parsed = getattr(compiled, "parsed", None) if compiled else None
    if parsed is None:
        return
    if parsed.identity.get("author_id") != agent.wallet.address():
        return
    try:
        save_dir = Path(agent.bittorrent.save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)
        with open(save_dir / ".self_authored_announces_sent.jsonl", "a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "community_id_hex": community_id.hex(),
                "message_name": message_name,
                "ts": time.time(),
            }) + "\n")
    except OSError:
        pass


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
        """Internal: snapshot of {balance, member_count,
        my_membership_status} computed from the local signed log +
        peer-log union.

        Returns an empty dict when no manifest is loaded; callers should
        guard against that.
        """
        state = agent.community_state()
        if state is None:
            return {}
        me = agent.community_reporter_id
        return {
            "balance_sats": state.balance_sats,
            "member_count": state.member_count,
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
        accepted_hashes = {d.entry_hash for d in state.donations}
        out: list[dict[str, Any]] = []
        for entry in ordered[-max(0, int(limit)):]:
            details = entry.get("details") or {}
            out.append({
                "action": entry.get("action"),
                "reporter_id": entry.get("reporter_id"),
                "timestamp": entry.get("timestamp"),
                "entry_hash": entry.get("entry_hash"),
                "amount_sats": details.get("amount_sats"),
                "accepted": entry.get("entry_hash") in accepted_hashes,
            })
        return out

    async def community_treasury_balance() -> dict[str, Any]:
        """Current treasury balance + member count + membership status.

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
        }

    async def community_donate_and_join(amount_sats: int) -> dict[str, Any]:
        """Compose a signed ``donation_intent`` entry and append it to our log.

        The amount is debited from this agent's synthetic wallet (so
        ``wallet_balance`` reflects the spend) before the entry is
        signed. The entry will propagate to peers via the signed_log pull
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
                # Our wallet address is the account id for the payment
                # ledger; recorded here so replay can map member -> wallet.
                "wallet_address": agent.wallet.address(),
            },
        )
        return {
            "entry_hash": entry["entry_hash"],
            "amount_sats": amount_sats,
            "network_id_hex": manifest.network_id.hex(),
        }

    async def community_join_via_peer(
        gatekeeper_mid: str, amount_sats: int, timeout_s: float = 8.0,
    ) -> dict[str, Any]:
        """Sign + append + ship a donation_intent to ``gatekeeper_mid``.

        v5.2 no-treasurer admission. The IMPORTANT step is (1): writing
        the signed entry to our own log. Membership is decided by every
        peer replaying the union of all signed logs (the signed_log pull
        loop replicates ours to them within one ``pull_interval_s``).
        The IPv8 ``CommunityJoinRequest`` round-trip in step (3) is a
        *latency optimisation* — a fast-path accept/reject — NOT the
        source of truth. If the wire reply never comes, admission still
        happens via replication; we just don't get the instant
        confirmation.

        Steps:
          1. ``community_donate_and_join(amount_sats)`` writes the signed
             entry to our local community log (debits wallet, runs
             local pre-checks). THIS is what actually admits us.
          2. Find the peer by mid prefix; ship the entry over the
             ``COMMUNITY_JOIN_REQUEST`` wire message.
          3. Briefly await the gatekeeper's accept/reject. Default
             ``timeout_s`` is 8s — bounded low ON PURPOSE: this tool is
             called under the cross-agent LLM turn lock, so a long block
             here stalls every other agent in the scenario. A loopback
             reply returns sub-second when the wire path is healthy; if
             it hasn't come in 8s it isn't coming this turn, and the
             entry is already replicating regardless.

        Returns ``{"entry_hash", "amount_sats", "accepted", "reason"}``.
        On wire timeout returns ``accepted=None`` with
        ``reason="wire_reply_timeout_admission_via_replication_pending"``
        — NOT an ``error`` key, because the local write succeeded and
        membership will resolve on the next replay. The LLM should treat
        a timed-out join as done, not retry it (retrying re-debits the
        wallet and writes a duplicate intent that replay rejects).
        """
        # Step 1 — sign + append locally. Reuses the pre-existing tool
        # so wallet debit, double-join check, cap check, etc. all run.
        # This is the load-bearing step: it admits us via replay.
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

        # Step 3 — find the peer and send. The wire reply is a
        # best-effort fast-path; its absence is not a failure.
        try:
            peer = _resolve_peer(agent, gatekeeper_mid)
        except KeyError as exc:
            return {"error": f"peer_not_found:{exc}"}
        future = agent.seedbox.request_community_join(peer, signed_entry)
        try:
            accepted, reason = await asyncio.wait_for(future, timeout=timeout_s)
        except asyncio.TimeoutError:
            return {
                "entry_hash": donate_result["entry_hash"],
                "amount_sats": amount_sats,
                "accepted": None,
                "reason": "wire_reply_timeout_admission_via_replication_pending",
                "note": (
                    "Local donation_intent written + debited. The "
                    "gatekeeper's wire ack did not arrive within "
                    f"{timeout_s}s, but membership is decided by signed-log "
                    "replay, not this ack. Your entry is replicating to "
                    "all peers now. Treat this turn as DONE — do NOT "
                    "call community_join_via_peer or community_donate_and_join "
                    "again (that re-debits your wallet and writes a "
                    "duplicate intent that replay rejects). Check "
                    "state.community.my_membership_status on a later tick."
                ),
            }

        return {
            "entry_hash": donate_result["entry_hash"],
            "amount_sats": amount_sats,
            "accepted": accepted,
            "reason": reason,
        }

    # ---- Payments (payment_request overlay + signed-log ledger) -------

    def _payment_overlay():
        """Return ``(community_id, compiled, instance)`` for the loaded
        ``payment_request`` overlay, or ``None`` if it isn't compiled yet."""
        for community_id in agent.registry.list_loaded():
            compiled = agent.registry._compiled[community_id]
            if compiled.parsed is not None and \
                    compiled.parsed.identity.get("name") == "payment_request":
                inst = agent.registry.get(community_id)
                if inst is not None:
                    return community_id, compiled, inst
        return None

    async def request_payment(amount_sats: int, memo: str = "") -> dict[str, Any]:
        """Broadcast a PAYMENT_REQUEST for ``amount_sats`` to every known peer.

        Communication only — the payment itself arrives later via a peer's
        ``send_payment`` (wallet transfer + signed-log entry + PAYMENT_NOTIFY).
        Returns ``{"sent_to": <n>}`` or an ``error`` field.
        """
        if not isinstance(amount_sats, int) or amount_sats < 1:
            return {"error": f"amount_sats must be a positive int; got {amount_sats!r}"}
        found = _payment_overlay()
        if found is None:
            return {"error": "payment_request_overlay_not_loaded"}
        _community_id, compiled, instance = found
        payload_cls = compiled.payload_classes.get("PAYMENT_REQUEST")
        if payload_cls is None:
            return {"error": "payment_request_overlay_missing_PAYMENT_REQUEST"}
        peers = list(agent.known_peers())
        if not peers:
            return {"error": "no_known_peers_for_request_payment"}
        for peer in peers:
            _wire_logger.info(
                "IPv8 send msg=PAYMENT_REQUEST peer=%s overlay=payment_request "
                "via=request_payment amount=%d",
                peer.mid.hex()[:12], amount_sats,
            )
            instance.ez_send(peer, payload_cls(amount_sats, memo.encode("utf-8")))
        from agent.wake_signal import signal_peers
        signal_peers(f"payment_request:{amount_sats}")
        return {"sent_to": len(peers), "amount_sats": amount_sats}

    async def send_payment(to_peer_mid: str, amount_sats: int) -> dict[str, Any]:
        """Send fake BTC to a peer: debit wallet, append a signed ``payment``
        log entry (the authoritative ledger record), and notify the peer.

        The recipient's wallet address is resolved from the PEER_INTRO
        metadata (``PeerMeta``) the peer shared on admission. Returns
        ``{"txid", "to_wallet", "amount_sats", "entry_hash"}`` or an
        ``error`` field. Errors never raise (tool-surface convention).
        """
        manifest = agent.network_manifest
        if manifest is None:
            return {"error": "no_manifest_loaded"}
        if not isinstance(amount_sats, int) or amount_sats < 1:
            return {"error": f"amount_sats must be a positive int; got {amount_sats!r}"}

        try:
            peer = _resolve_peer(agent, to_peer_mid)
        except KeyError as exc:
            return {"error": f"peer_not_found:{exc}"}

        meta = agent.seedbox.peer_meta.get(peer.mid) if agent.seedbox else None
        to_wallet = getattr(meta, "wallet_address", "") if meta else ""
        if not to_wallet:
            return {"error": "recipient_wallet_unknown (no PEER_INTRO received yet)"}

        # Debit the synthetic wallet (raises ValueError on insufficient funds).
        try:
            txid = agent.wallet.send(to_wallet, amount_sats)
        except ValueError as exc:
            return {"error": f"wallet_send_failed: {exc}"}

        # The authoritative record: a signed payment entry every peer replays.
        entry = agent.community_log.append_event(
            reporter_id=agent.community_reporter_id,
            subject_id=agent.community_reporter_id,
            action="payment",
            details={
                "network_id_hex": manifest.network_id.hex(),
                "to_wallet": to_wallet,
                "amount_sats": amount_sats,
            },
        )

        # Courtesy heads-up over the overlay (best-effort; ledger is the truth).
        found = _payment_overlay()
        if found is not None:
            _community_id, compiled, instance = found
            notify_cls = compiled.payload_classes.get("PAYMENT_NOTIFY")
            if notify_cls is not None:
                _wire_logger.info(
                    "IPv8 send msg=PAYMENT_NOTIFY peer=%s overlay=payment_request "
                    "via=send_payment amount=%d",
                    peer.mid.hex()[:12], amount_sats,
                )
                instance.ez_send(peer, notify_cls(amount_sats, txid.encode("utf-8")))

        from agent.wake_signal import signal_peers
        signal_peers(f"payment_sent:{amount_sats}")
        return {
            "txid": txid,
            "to_wallet": to_wallet,
            "amount_sats": amount_sats,
            "entry_hash": entry["entry_hash"],
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

        out: list[dict[str, Any]] = []
        for cid in agent.registry.list_loaded():
            entry = overlay_to_dict(agent.registry._compiled[cid])
            # Surface anything this overlay has RECEIVED from peers.
            # overlay_to_dict only sees the compiled class (static
            # schema); the live instance is where async responses land
            # (e.g. content_community.response_cache holds SEARCH hits).
            # Without this, an agent that fired SEARCH_REQUEST via
            # overlay_invoke (which is fire-and-forget, returns just
            # {"sent": true}) has NO way to ever observe the
            # SEARCH_RESPONSE — the magnet it needs for torrent_fetch
            # is invisible and concept step 5 (retrieve file) is
            # structurally unreachable. Cap the list so a chatty
            # overlay can't blow the prompt's token budget.
            instance = agent.registry.get(cid)
            received = getattr(instance, "response_cache", None)
            if isinstance(received, list) and received:
                entry["received"] = received[-20:]
            out.append(entry)
        return out

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
        instance = await agent.registry.aload(
            md_bytes.decode("utf-8"),
            provenance=f"received_from:{peer.mid.hex()[:12]}",
        )
        cid_hex = instance.community_id.hex()
        # Wake peers: a successor that just adopted this overlay might be the
        # base for someone else's evolution; the genesis author may also be
        # waiting on adoption confirmation before issuing the next ANNOUNCE.
        from agent.wake_signal import signal_peers
        signal_peers(f"overlay_adopted:{cid_hex[:12]}")
        return {
            "community_id_hex": cid_hex,
            "loaded": True,
        }

    async def overlay_publish(md_text: str) -> str:
        md_hash = agent.seedbox.publish_overlay(md_text)
        # Also load it locally so we serve traffic on the new overlay.
        await agent.registry.aload(md_text, provenance="published")
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

        from protocol.compiler import _coerce_field_value  # type: ignore[attr-defined]
        coerced = [_coerce_field_value(v) for v in fields.values()]
        peer = _resolve_peer(agent, peer_mid)
        _wire_logger.info(
            "IPv8 send msg=%s peer=%s overlay=%s via=overlay_invoke",
            message_name,
            peer.mid.hex()[:12],
            compiled.parsed.identity.get("name", compiled.origin) if compiled.parsed else compiled.origin,
        )
        instance.ez_send(peer, payload_cls(*coerced))
        _maybe_record_self_authored_announce(agent, community_id, message_name)
        # Wake the peer (and any other peer that cares) — e.g. a successor
        # waiting on observed-usage evidence from the genesis author.
        from agent.wake_signal import signal_peers
        signal_peers(f"overlay_message:{message_name}")
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

    async def content_search_and_fetch(
        query: str = "",
        timeout_s: float = 10.0,
        pick: str | int = "random",
    ) -> dict[str, Any]:
        """Search content_community peers, wait for a response, then fetch one magnet from the result set.

        ``pick`` controls which result is fetched: ``"random"`` (default)
        chooses uniformly across matches, ``"first"`` returns the first
        result in declared order, and an ``int`` selects that 0-based
        index (out-of-range falls back to ``"random"``).

        Default ``query=""`` matches every entry in the peer's
        ``local_index`` — the content_community handler returns the full
        catalogue (up to ``MAX_RESULTS``) when the query is empty. Pass a
        non-empty string to filter by name/tag substring.

        Implementation lives in ``agent.content_fetch`` so the MCP server
        path (``agent.mcp_server``) shares the exact same hash-verified
        IPv8 transfer.
        """
        from agent.content_fetch import content_search_and_fetch_impl
        return await content_search_and_fetch_impl(
            agent, query=query, timeout_s=timeout_s, pick=pick,
        )

    async def content_fetch_via_transfer(
        query: str = "",
        timeout_s: float = 20.0,
        pick: str | int = "random",
    ) -> dict[str, Any]:
        """Search content_community, then fetch the file over the ``file_transfer``
        overlay (chunked, hash-verified) instead of the single-shot seedbox path.

        Same discovery + ``pick`` semantics as ``content_search_and_fetch``; the
        bytes move as numbered CHUNKs reassembled + verified by the compiled
        ``file_transfer`` overlay. Implementation in ``agent.content_fetch`` so
        the MCP server path shares it.
        """
        from agent.content_fetch import content_fetch_via_transfer_impl
        return await content_fetch_via_transfer_impl(
            agent, query=query, timeout_s=timeout_s, pick=pick,
        )

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
        """Author a new overlay protocol spec, publish it, and offer it to peers.

        Implementation lives in ``agent.overlay_authoring_tool`` so the MCP
        server path shares the exact same synthesis + publish + gossip logic.
        """
        from agent.overlay_authoring_tool import overlay_author_and_publish_impl
        return await overlay_author_and_publish_impl(
            agent, name=name, version=version, description=description,
            messages=messages, change_summary=change_summary,
            runtime_state=runtime_state, constants=constants, samples=samples,
            supersedes_cid_hex=supersedes_cid_hex,
        )

    # ---- Spec definitions ---------------------------------------------

    P_NONE = {"type": "object", "properties": {}, "additionalProperties": False}

    # JSON schema for the structured overlay-authoring args. The LLM fills
    # message/field design; the tool synthesizes the byte-exact .md.
    P_AUTHOR_OVERLAY = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "snake_case overlay name (e.g. download_announce)"},
            "version": {"type": "string", "description": "semver, e.g. 1.0.0"},
            "description": {"type": "string", "description": "one-line summary"},
            "change_summary": {"type": "string", "description": "1-2 sentences: what this version does / changes"},
            "messages": {
                "type": "array",
                "description": "one entry per wire message",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "SCREAMING_SNAKE_CASE"},
                        "msg_id": {"type": "integer", "minimum": 0, "maximum": 255},
                        "fields": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string", "description": "snake_case field name"},
                                    "encoding": {"type": "string",
                                                  "description": "one of: uint8, uint16-be, uint32-be, uint64-be, bool, varlenH, varlenH-utf8, varlenH-msgpack, bytes20, bytes32"},
                                    "description": {"type": "string"},
                                },
                                "required": ["name", "encoding"],
                            },
                        },
                        "handler": {"type": "string", "description": "prose: what the receiver does on receipt"},
                    },
                    "required": ["name", "msg_id", "fields", "handler"],
                },
            },
            "runtime_state": {
                "type": "array",
                "description": "optional public mutable attributes the handler reads/writes",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "type": {"type": "string", "description": "list[dict] / dict / int / str / bool / bytes / set"},
                        "description": {"type": "string"},
                    },
                    "required": ["name", "type"],
                },
            },
            "samples": {
                "type": "object",
                "description": "optional {MESSAGE_NAME: {field: example_value}} for a populated test vector",
            },
            "supersedes_cid_hex": {
                "type": "string",
                "description": "optional 40-char community_id of a loaded same-name overlay this version replaces",
            },
        },
        "required": ["name", "version", "description", "change_summary", "messages"],
        "additionalProperties": False,
    }

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
             "(donation_intent) across this agent's chain and every "
             "known peer's chain, with an ``accepted`` flag per entry.",
             {"type": "object",
              "properties": {
                  "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
              },
              "additionalProperties": False},
             community_log_list_recent),

        Tool("community_treasury_balance",
             "Snapshot of the community's no-treasurer treasury: "
             "balance_sats (sum of accepted donations), member_count, "
             "and our own membership status.",
             P_NONE, community_treasury_balance),

        Tool("community_member_count",
             "Number of admitted members + our own membership status.",
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

        Tool("request_payment",
             "Broadcast a PAYMENT_REQUEST for amount_sats to every known "
             "peer over the payment_request overlay. Communication only — a "
             "peer fulfils it later via send_payment. Requires the "
             "payment_request overlay to be loaded.",
             {"type": "object",
              "properties": {
                  "amount_sats": {"type": "integer", "minimum": 1,
                                  "description": "satoshis to request"},
                  "memo": {"type": "string", "default": "",
                           "description": "optional free-text reason"},
              },
              "required": ["amount_sats"],
              "additionalProperties": False},
             request_payment),

        Tool("send_payment",
             "Send fake BTC to a peer: debit our wallet, append a signed "
             "payment entry to the community log (the authoritative ledger "
             "replayed into community.balances), and notify the peer via "
             "PAYMENT_NOTIFY. The recipient wallet is resolved from the "
             "peer's PEER_INTRO metadata.",
             {"type": "object",
              "properties": {
                  "to_peer_mid": {"type": "string",
                                  "description": "hex prefix of the recipient peer's IPv8 mid"},
                  "amount_sats": {"type": "integer", "minimum": 1},
              },
              "required": ["to_peer_mid", "amount_sats"],
              "additionalProperties": False},
             send_payment),

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

        Tool("content_search_and_fetch",
             "Paper-demo helper: send SEARCH_REQUEST on content_community if needed, "
             "read response_cache, and fetch one returned magnet. By default the "
             "result is chosen at random across all matches; pass pick='first' or a "
             "0-based integer index to override. Use this instead of repeating "
             "SEARCH_REQUEST when response_cache already has a result.",
             {"type": "object",
              "properties": {
                  "query": {"type": "string", "default": ""},
                  "timeout_s": {"type": "number", "default": 10.0},
                  "pick": {
                      "oneOf": [
                          {"type": "string", "enum": ["random", "first"]},
                          {"type": "integer", "minimum": 0},
                      ],
                      "default": "random",
                  },
              },
              "additionalProperties": False},
             content_search_and_fetch),

        Tool("content_fetch_via_transfer",
             "Like content_search_and_fetch, but the file is transferred over the "
             "file_transfer overlay (chunked: manifest -> numbered CHUNKs -> "
             "reassembly -> whole-content sha256 verify) instead of the single-shot "
             "seedbox path. Same query/pick semantics.",
             {"type": "object",
              "properties": {
                  "query": {"type": "string", "default": ""},
                  "timeout_s": {"type": "number", "default": 20.0},
                  "pick": {
                      "oneOf": [
                          {"type": "string", "enum": ["random", "first"]},
                          {"type": "integer", "minimum": 0},
                      ],
                      "default": "random",
                  },
              },
              "additionalProperties": False},
             content_fetch_via_transfer),

        Tool("torrent_stats",
             "Snapshot of all currently-known torrents (downloads + seeds).",
             P_NONE, torrent_stats),

        Tool("overlay_author_and_publish",
             "Author a NEW overlay protocol spec and publish it to the network. "
             "You describe the protocol's messages + fields + handler semantics "
             "as structured JSON; the tool synthesizes the markdown descriptor "
             "(including byte-exact test vectors), compiles + installs it locally, "
             "and offers it to every peer so they can adopt it. Pass "
             "supersedes_cid_hex to publish a new VERSION of an overlay you "
             "already run (same name).",
             P_AUTHOR_OVERLAY, overlay_author_and_publish),
    ])
