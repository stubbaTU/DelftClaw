"""SeedboxCommunity: admit-by-donation + overlay + network-manifest distribution.

Wire protocol:

    JoinRequestPayload(donation_txid: bytes)         joiner -> gatekeeper
    JoinResponsePayload(accepted: bool)              gatekeeper -> joiner
    OverlayOfferPayload(md_hash: 20 bytes)           peer -> peer
    OverlayRequestPayload(md_hash: 20 bytes)         peer -> peer
    OverlayDeliveryPayload(md_hash, md_text)         peer -> peer
    ManifestOfferPayload(md_hash: 20 bytes)          peer -> peer
    ManifestRequestPayload(md_hash: 20 bytes)        peer -> peer
    ManifestDeliveryPayload(md_hash, md_text)        peer -> peer
    PeerIntroPayload(wallet_address, known_overlays) peer -> peer (post-admission)

Joiner-side helpers:

    ``request_join(gatekeeper, donation_txid) -> asyncio.Future[bool]``
        send JOIN_REQUEST + return a future for the decision.

    ``fetch_overlay(peer, md_hash) -> asyncio.Future[bytes]``
        send OVERLAY_REQUEST + return a future for the md_text bytes.

    ``fetch_manifest(peer, md_hash) -> asyncio.Future[bytes]``
        send MANIFEST_REQUEST + return a future for the manifest bytes.

Publisher-side:

    ``publish_overlay(md_text)`` / ``publish_manifest(md_text)``
        register a descriptor / manifest the node is willing to serve
        via {OVERLAY,MANIFEST}_DELIVERY when peers ask for it (looked
        up by sha1 of the canonicalized bytes).

Manifests and overlays share the same canonicalization + sha1[:20]
derivation but live on different message ids so the receiver knows
which document type it just got, and so a malicious peer cannot trick
a joiner into compiling a manifest as a runnable community.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from typing import Callable, Optional

import msgpack
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver

from admission.donation_verifier import DonationVerifier


# Mirror the redteam pull-loop's HTTP access-log shape: one line per
# wire event, written via the standard logger so systemd journals
# capture it alongside uvicorn's ``/head`` / ``/entries`` lines. Grep
# with ``journalctl -u delftclaw-mcp@... | grep IPv8``.
_wire_logger = logging.getLogger("delftclaw.communication.wire")


def _peer_tag(peer: Peer) -> str:
    """Short, log-friendly identifier for a peer (first 6 bytes of mid hex)."""
    try:
        return peer.mid.hex()[:12]
    except Exception:
        return "??"


def _log_wire(direction: str, msg: str, peer: Peer, **fields: object) -> None:
    """Emit one structured line per wire event.

    ``direction`` is ``send`` or ``recv``. ``msg`` is the payload class
    name without the ``Payload`` suffix. Extra ``fields`` are joined as
    ``key=value`` pairs in the order given.
    """
    rendered = " ".join(f"{k}={v}" for k, v in fields.items())
    suffix = (" " + rendered) if rendered else ""
    _wire_logger.info("IPv8 %s msg=%s peer=%s%s", direction, msg, _peer_tag(peer), suffix)


@dataclass(frozen=True)
class PeerMeta:
    """Live metadata a peer publishes about itself in its PEER_INTRO."""

    wallet_address: str
    known_overlays: tuple[bytes, ...]   # each entry is a 20-byte overlay/manifest id


# Cap on a single OVERLAY_DELIVERY payload — protects against a peer
# trying to flood us with arbitrarily large markdown blobs.
MAX_OVERLAY_BYTES = 64 * 1024


def _canonicalize(text: str) -> bytes:
    """Mirror of ``protocol.compiler.canonicalize_md`` (kept local to avoid the import cycle)."""
    text = text.replace("\r\n", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return ("\n".join(lines)).encode("utf-8")


def overlay_id(md_text: str) -> bytes:
    """20-byte sha1-prefix id of an overlay descriptor's canonicalized bytes."""
    return hashlib.sha1(_canonicalize(md_text)).digest()[:20]


def manifest_id(md_text: str) -> bytes:
    """20-byte sha1-prefix id of a network-manifest's canonicalized bytes.

    Same derivation as ``overlay_id``; aliased for call-site clarity.
    """
    return hashlib.sha1(_canonicalize(md_text)).digest()[:20]


@vp_compile
class JoinRequestPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenH"]
    names = ["donation_txid"]


@vp_compile
class JoinResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?"]
    names = ["accepted"]


@vp_compile
class OverlayOfferPayload(VariablePayload):
    msg_id = 3
    format_list = ["20s"]
    names = ["md_hash"]


@vp_compile
class OverlayRequestPayload(VariablePayload):
    msg_id = 4
    format_list = ["20s"]
    names = ["md_hash"]


@vp_compile
class OverlayDeliveryPayload(VariablePayload):
    msg_id = 5
    format_list = ["20s", "varlenH"]
    names = ["md_hash", "md_text"]


@vp_compile
class ManifestOfferPayload(VariablePayload):
    msg_id = 6
    format_list = ["20s"]
    names = ["md_hash"]


@vp_compile
class ManifestRequestPayload(VariablePayload):
    msg_id = 7
    format_list = ["20s"]
    names = ["md_hash"]


@vp_compile
class ManifestDeliveryPayload(VariablePayload):
    msg_id = 8
    format_list = ["20s", "varlenH"]
    names = ["md_hash", "md_text"]


@vp_compile
class PeerIntroPayload(VariablePayload):
    """Live introduction sent after admission so peers learn each other's
    wallet address (for future BTC ops) and overlay catalogue (so they
    know which protocols this peer already serves)."""

    msg_id = 9
    # wallet_address: utf-8 bech32 string carried as raw bytes;
    # known_overlays: msgpack-encoded list of 20-byte overlay ids.
    format_list = ["varlenH", "varlenH"]
    names = ["wallet_address", "known_overlays"]


@vp_compile
class CommunityJoinRequestPayload(VariablePayload):
    """Phase-5 community admission: joiner ships a JSON-serialised
    signed donation_intent entry the gatekeeper validates against the
    community-log replay state. Coexists with the legacy
    ``JoinRequestPayload`` (msg_id=1) so older agents still admit by
    raw-txid. New agents prefer this path because it requires no
    trusted gatekeeper key custody."""

    msg_id = 10
    # signed_entry: utf-8 JSON of the signed-log self-entry the donor
    # appended to their own SignedAppendOnlyLog. The gatekeeper
    # re-verifies its signature + identity binding and replays the
    # community state to decide accept/reject.
    format_list = ["varlenH"]
    names = ["signed_entry"]


@vp_compile
class CommunityJoinResponsePayload(VariablePayload):
    """Reply to CommunityJoinRequest. ``reason`` is a short utf-8 string
    naming the failure mode for the LLM-facing log; empty on accept."""

    msg_id = 11
    format_list = ["?", "varlenH"]
    names = ["accepted", "reason"]


# Optional callback signatures: invoked when this node receives an OFFER
# for a hash it doesn't already know about.
OverlayOfferCallback = Callable[[Peer, bytes], None]
ManifestOfferCallback = Callable[[Peer, bytes], None]
PeerIntroCallback = Callable[[Peer, PeerMeta], None]

# Phase 5: callback signature for the community-log admission path.
# Receives the JSON-decoded signed entry the joiner shipped; returns
# ``(accepted, reason)``. The community.community_state-replay layer
# is the source of truth — this callback just plumbs the agent runtime
# to the wire handler.
CommunityJoinCallback = Callable[[Peer, dict], tuple[bool, str]]


class SeedboxCommunity(Community, PeerObserver):
    """Bootstrap overlay: donation-gated admission + overlay-descriptor exchange."""

    community_id = b"openclaw_seedbox_v1\x00"  # exactly 20 bytes per IPv8 contract.

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self._verifier: Optional[DonationVerifier] = None

        # JOIN bookkeeping.
        self._pending_joins: dict[bytes, asyncio.Future[bool]] = {}

        # OVERLAY bookkeeping.
        self._published: dict[bytes, str] = {}              # md_hash -> md_text we serve
        self._known_offers: dict[bytes, set[bytes]] = {}    # md_hash -> set of peer mids that offered
        self._pending_fetches: dict[bytes, asyncio.Future[bytes]] = {}
        self._offer_callback: Optional[OverlayOfferCallback] = None

        # MANIFEST bookkeeping (parallel to OVERLAY).
        self._published_manifests: dict[bytes, str] = {}
        self._known_manifest_offers: dict[bytes, set[bytes]] = {}
        self._pending_manifest_fetches: dict[bytes, asyncio.Future[bytes]] = {}
        self._manifest_offer_callback: Optional[ManifestOfferCallback] = None

        # PEER_INTRO bookkeeping — populated on admission round-trip.
        self._wallet_address: Optional[str] = None        # set by configure()
        self._peer_meta: dict[bytes, PeerMeta] = {}        # peer.mid -> PeerMeta
        self._peer_intro_callback: Optional[PeerIntroCallback] = None

        # COMMUNITY_JOIN_REQUEST bookkeeping — Phase 5 admission path.
        self._pending_community_joins: dict[bytes, asyncio.Future[tuple[bool, str]]] = {}
        self._community_join_callback: Optional[CommunityJoinCallback] = None

        self.add_message_handler(JoinRequestPayload, self.on_join_request)
        self.add_message_handler(JoinResponsePayload, self.on_join_response)
        self.add_message_handler(OverlayOfferPayload, self.on_overlay_offer)
        self.add_message_handler(OverlayRequestPayload, self.on_overlay_request)
        self.add_message_handler(OverlayDeliveryPayload, self.on_overlay_delivery)
        self.add_message_handler(ManifestOfferPayload, self.on_manifest_offer)
        self.add_message_handler(ManifestRequestPayload, self.on_manifest_request)
        self.add_message_handler(ManifestDeliveryPayload, self.on_manifest_delivery)
        self.add_message_handler(PeerIntroPayload, self.on_peer_intro)
        self.add_message_handler(CommunityJoinRequestPayload, self.on_community_join_request)
        self.add_message_handler(CommunityJoinResponsePayload, self.on_community_join_response)

    # ------------------------------------------------------------------
    # Configuration / wiring
    # ------------------------------------------------------------------

    def configure(
        self,
        *,
        verifier: Optional[DonationVerifier] = None,
        offer_callback: Optional[OverlayOfferCallback] = None,
        manifest_offer_callback: Optional[ManifestOfferCallback] = None,
        wallet_address: Optional[str] = None,
        peer_intro_callback: Optional[PeerIntroCallback] = None,
        community_join_callback: Optional[CommunityJoinCallback] = None,
    ) -> None:
        """Wire optional collaborators after construction."""
        if verifier is not None:
            self._verifier = verifier
        if offer_callback is not None:
            self._offer_callback = offer_callback
        if manifest_offer_callback is not None:
            self._manifest_offer_callback = manifest_offer_callback
        if wallet_address is not None:
            self._wallet_address = wallet_address
        if peer_intro_callback is not None:
            self._peer_intro_callback = peer_intro_callback
        if community_join_callback is not None:
            self._community_join_callback = community_join_callback

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, peer: Peer) -> None:
        pass

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    # ------------------------------------------------------------------
    # JOIN flow
    # ------------------------------------------------------------------

    def request_join(self, gatekeeper: Peer, donation_txid: bytes) -> asyncio.Future[bool]:
        """Joiner-side: send JOIN_REQUEST; the returned future resolves with the decision."""
        loop = asyncio.get_event_loop()
        future: asyncio.Future[bool] = loop.create_future()
        self._pending_joins[gatekeeper.mid] = future
        _log_wire("send", "JoinRequest", gatekeeper, txid=donation_txid.hex()[:16])
        self.ez_send(gatekeeper, JoinRequestPayload(donation_txid))
        return future

    @lazy_wrapper(JoinRequestPayload)
    def on_join_request(self, peer: Peer, payload: JoinRequestPayload) -> None:
        _log_wire("recv", "JoinRequest", peer, txid=payload.donation_txid.hex()[:16])
        if self._verifier is None:
            _log_wire("send", "JoinResponse", peer, accepted=False, reason="no_verifier")
            self.ez_send(peer, JoinResponsePayload(False))
            return
        result = self._verifier.verify(payload.donation_txid.hex())
        if result.accepted:
            self.network.add_verified_peer(peer)
        _log_wire("send", "JoinResponse", peer, accepted=result.accepted)
        self.ez_send(peer, JoinResponsePayload(result.accepted))
        if result.accepted:
            self._send_peer_intro(peer)

    @lazy_wrapper(JoinResponsePayload)
    def on_join_response(self, peer: Peer, payload: JoinResponsePayload) -> None:
        _log_wire("recv", "JoinResponse", peer, accepted=payload.accepted)
        future = self._pending_joins.pop(peer.mid, None)
        if future is not None and not future.done():
            future.set_result(payload.accepted)
        if payload.accepted:
            self._send_peer_intro(peer)

    # ------------------------------------------------------------------
    # COMMUNITY_JOIN flow (Phase 5 — admit-by-signed-log-entry)
    # ------------------------------------------------------------------

    def request_community_join(
        self, gatekeeper: Peer, signed_entry: dict,
    ) -> asyncio.Future[tuple[bool, str]]:
        """Joiner-side: ship a JSON-serialised signed donation_intent entry.

        Returns a future resolving to ``(accepted, reason)``.
        Compared to the legacy ``request_join``, the joiner does NOT
        rely on the gatekeeper having a real Bitcoin verifier — the
        gatekeeper instead caches the entry in its own peer-log and
        replays community state to decide.
        """
        import json as _json
        loop = asyncio.get_event_loop()
        future: asyncio.Future[tuple[bool, str]] = loop.create_future()
        self._pending_community_joins[gatekeeper.mid] = future
        payload_bytes = _json.dumps(signed_entry).encode("utf-8")
        _log_wire(
            "send", "CommunityJoinRequest", gatekeeper,
            entry_bytes=len(payload_bytes),
            entry_type=signed_entry.get("type") if isinstance(signed_entry, dict) else "?",
        )
        self.ez_send(gatekeeper, CommunityJoinRequestPayload(payload_bytes))
        return future

    @lazy_wrapper(CommunityJoinRequestPayload)
    def on_community_join_request(
        self, peer: Peer, payload: CommunityJoinRequestPayload,
    ) -> None:
        import json as _json
        _log_wire(
            "recv", "CommunityJoinRequest", peer,
            entry_bytes=len(payload.signed_entry),
        )
        if self._community_join_callback is None:
            _log_wire("send", "CommunityJoinResponse", peer, accepted=False, reason="no_callback")
            self.ez_send(
                peer,
                CommunityJoinResponsePayload(False, b"no_community_join_callback"),
            )
            return
        try:
            entry = _json.loads(payload.signed_entry.decode("utf-8"))
        except (UnicodeDecodeError, _json.JSONDecodeError) as exc:
            _log_wire("send", "CommunityJoinResponse", peer, accepted=False, reason=f"malformed:{exc}")
            self.ez_send(
                peer,
                CommunityJoinResponsePayload(False, f"malformed_entry:{exc}".encode("utf-8")),
            )
            return
        if not isinstance(entry, dict):
            _log_wire("send", "CommunityJoinResponse", peer, accepted=False, reason="not_object")
            self.ez_send(peer, CommunityJoinResponsePayload(False, b"entry_not_object"))
            return
        accepted, reason = self._community_join_callback(peer, entry)
        if accepted:
            self.network.add_verified_peer(peer)
        _log_wire(
            "send", "CommunityJoinResponse", peer,
            accepted=bool(accepted), reason=(reason or "")[:60],
        )
        self.ez_send(
            peer,
            CommunityJoinResponsePayload(bool(accepted), (reason or "").encode("utf-8")),
        )
        if accepted:
            self._send_peer_intro(peer)

    @lazy_wrapper(CommunityJoinResponsePayload)
    def on_community_join_response(
        self, peer: Peer, payload: CommunityJoinResponsePayload,
    ) -> None:
        future = self._pending_community_joins.pop(peer.mid, None)
        reason = ""
        try:
            reason = payload.reason.decode("utf-8")
        except UnicodeDecodeError:
            reason = "<reason: invalid utf-8>"
        _log_wire(
            "recv", "CommunityJoinResponse", peer,
            accepted=bool(payload.accepted), reason=reason[:60],
        )
        if future is not None and not future.done():
            future.set_result((bool(payload.accepted), reason))
        if payload.accepted:
            self._send_peer_intro(peer)

    # ------------------------------------------------------------------
    # OVERLAY descriptor exchange
    # ------------------------------------------------------------------

    def publish_overlay(self, md_text: str) -> bytes:
        """Make ``md_text`` available to peers who ask for its sha1-prefix id.

        Returns the 20-byte id so the caller can advertise it.
        """
        md_hash = overlay_id(md_text)
        self._published[md_hash] = md_text
        return md_hash

    def offer_overlay(self, peer: Peer, md_hash: bytes) -> None:
        """Tell ``peer`` we serve an overlay with this id (no payload sent)."""
        if len(md_hash) != 20:
            raise ValueError("md_hash must be exactly 20 bytes")
        _log_wire("send", "OverlayOffer", peer, md_hash=md_hash.hex()[:16])
        self.ez_send(peer, OverlayOfferPayload(md_hash))

    def fetch_overlay(self, peer: Peer, md_hash: bytes) -> asyncio.Future[bytes]:
        """Joiner-side: send OVERLAY_REQUEST; resolve with the delivered md_text bytes."""
        if len(md_hash) != 20:
            raise ValueError("md_hash must be exactly 20 bytes")
        loop = asyncio.get_event_loop()
        future: asyncio.Future[bytes] = loop.create_future()
        # Key by md_hash, not peer mid — multiple peers may serve the same overlay
        # and we accept the first delivery.
        self._pending_fetches[md_hash] = future
        _log_wire("send", "OverlayRequest", peer, md_hash=md_hash.hex()[:16])
        self.ez_send(peer, OverlayRequestPayload(md_hash))
        return future

    @lazy_wrapper(OverlayOfferPayload)
    def on_overlay_offer(self, peer: Peer, payload: OverlayOfferPayload) -> None:
        _log_wire("recv", "OverlayOffer", peer, md_hash=payload.md_hash.hex()[:16])
        self._known_offers.setdefault(payload.md_hash, set()).add(peer.mid)
        cb = self._offer_callback
        if cb is not None:
            cb(peer, payload.md_hash)

    @lazy_wrapper(OverlayRequestPayload)
    def on_overlay_request(self, peer: Peer, payload: OverlayRequestPayload) -> None:
        _log_wire("recv", "OverlayRequest", peer, md_hash=payload.md_hash.hex()[:16])
        md_text = self._published.get(payload.md_hash)
        if md_text is None:
            return  # silently ignore; requester times out at its end
        body = md_text.encode("utf-8")
        if len(body) > MAX_OVERLAY_BYTES:
            return  # we never publish anything that big; defensive drop
        _log_wire(
            "send", "OverlayDelivery", peer,
            md_hash=payload.md_hash.hex()[:16], bytes=len(body),
        )
        self.ez_send(peer, OverlayDeliveryPayload(payload.md_hash, body))

    @lazy_wrapper(OverlayDeliveryPayload)
    def on_overlay_delivery(self, peer: Peer, payload: OverlayDeliveryPayload) -> None:
        _log_wire(
            "recv", "OverlayDelivery", peer,
            md_hash=payload.md_hash.hex()[:16], bytes=len(payload.md_text),
        )
        if len(payload.md_text) > MAX_OVERLAY_BYTES:
            return
        # Verify the delivery actually matches the hash before resolving
        # the waiter — otherwise a malicious peer could feed us anything.
        delivered_text = payload.md_text.decode("utf-8", errors="replace")
        if overlay_id(delivered_text) != payload.md_hash:
            return
        future = self._pending_fetches.pop(payload.md_hash, None)
        if future is not None and not future.done():
            future.set_result(payload.md_text)

    # ------------------------------------------------------------------
    # NETWORK MANIFEST exchange (parallel to OVERLAY descriptor exchange)
    # ------------------------------------------------------------------

    def publish_manifest(self, md_text: str) -> bytes:
        """Make ``md_text`` available to peers who ask for its sha1-prefix id.

        Returns the 20-byte id so the caller can advertise it.
        """
        md_hash = manifest_id(md_text)
        self._published_manifests[md_hash] = md_text
        return md_hash

    def offer_manifest(self, peer: Peer, md_hash: bytes) -> None:
        """Tell ``peer`` we serve a manifest with this id (no payload sent)."""
        if len(md_hash) != 20:
            raise ValueError("md_hash must be exactly 20 bytes")
        _log_wire("send", "ManifestOffer", peer, md_hash=md_hash.hex()[:16])
        self.ez_send(peer, ManifestOfferPayload(md_hash))

    def fetch_manifest(self, peer: Peer, md_hash: bytes) -> asyncio.Future[bytes]:
        """Joiner-side: send MANIFEST_REQUEST; resolve with the delivered manifest_md bytes."""
        if len(md_hash) != 20:
            raise ValueError("md_hash must be exactly 20 bytes")
        loop = asyncio.get_event_loop()
        future: asyncio.Future[bytes] = loop.create_future()
        self._pending_manifest_fetches[md_hash] = future
        _log_wire("send", "ManifestRequest", peer, md_hash=md_hash.hex()[:16])
        self.ez_send(peer, ManifestRequestPayload(md_hash))
        return future

    @lazy_wrapper(ManifestOfferPayload)
    def on_manifest_offer(self, peer: Peer, payload: ManifestOfferPayload) -> None:
        _log_wire("recv", "ManifestOffer", peer, md_hash=payload.md_hash.hex()[:16])
        self._known_manifest_offers.setdefault(payload.md_hash, set()).add(peer.mid)
        cb = self._manifest_offer_callback
        if cb is not None:
            cb(peer, payload.md_hash)

    @lazy_wrapper(ManifestRequestPayload)
    def on_manifest_request(self, peer: Peer, payload: ManifestRequestPayload) -> None:
        _log_wire("recv", "ManifestRequest", peer, md_hash=payload.md_hash.hex()[:16])
        md_text = self._published_manifests.get(payload.md_hash)
        if md_text is None:
            return  # silently ignore; requester times out at its end
        body = md_text.encode("utf-8")
        if len(body) > MAX_OVERLAY_BYTES:
            return  # we never publish anything that big; defensive drop
        _log_wire(
            "send", "ManifestDelivery", peer,
            md_hash=payload.md_hash.hex()[:16], bytes=len(body),
        )
        self.ez_send(peer, ManifestDeliveryPayload(payload.md_hash, body))

    @lazy_wrapper(ManifestDeliveryPayload)
    def on_manifest_delivery(self, peer: Peer, payload: ManifestDeliveryPayload) -> None:
        _log_wire(
            "recv", "ManifestDelivery", peer,
            md_hash=payload.md_hash.hex()[:16], bytes=len(payload.md_text),
        )
        if len(payload.md_text) > MAX_OVERLAY_BYTES:
            return
        delivered_text = payload.md_text.decode("utf-8", errors="replace")
        if manifest_id(delivered_text) != payload.md_hash:
            return
        future = self._pending_manifest_fetches.pop(payload.md_hash, None)
        if future is not None and not future.done():
            future.set_result(payload.md_text)

    # ------------------------------------------------------------------
    # PEER_INTRO — live wallet + overlay catalogue exchange post-admission
    # ------------------------------------------------------------------

    def _send_peer_intro(self, peer: Peer) -> None:
        """Send our wallet address + the overlay ids we serve to ``peer``.

        Called automatically on both sides of the admission round-trip
        once accept=True. A node that hasn't been configured with a
        wallet_address silently skips the send (the receiving side
        simply won't get an entry for us in ``_peer_meta``).
        """
        if self._wallet_address is None:
            return
        overlays = sorted(self._published.keys())
        body = msgpack.packb(overlays, use_bin_type=True)
        _log_wire(
            "send", "PeerIntro", peer,
            wallet=self._wallet_address[:16], overlays=len(overlays),
        )
        self.ez_send(
            peer,
            PeerIntroPayload(
                wallet_address=self._wallet_address.encode("utf-8"),
                known_overlays=body,
            ),
        )

    @lazy_wrapper(PeerIntroPayload)
    def on_peer_intro(self, peer: Peer, payload: PeerIntroPayload) -> None:
        try:
            addr = payload.wallet_address.decode("utf-8")
        except UnicodeDecodeError:
            _log_wire("recv", "PeerIntro", peer, dropped="invalid_wallet_utf8")
            return  # malformed; drop
        try:
            raw = msgpack.unpackb(payload.known_overlays, raw=False)
        except Exception:
            _log_wire("recv", "PeerIntro", peer, wallet=addr[:16], dropped="overlays_unpack_failed")
            return  # malformed; drop
        if not isinstance(raw, list):
            _log_wire("recv", "PeerIntro", peer, wallet=addr[:16], dropped="overlays_not_list")
            return
        overlays: list[bytes] = []
        for h in raw:
            if isinstance(h, (bytes, bytearray)) and len(h) == 20:
                overlays.append(bytes(h))
        _log_wire("recv", "PeerIntro", peer, wallet=addr[:16], overlays=len(overlays))
        self.network.add_verified_peer(peer)
        meta = PeerMeta(wallet_address=addr, known_overlays=tuple(overlays))
        self._peer_meta[peer.mid] = meta
        cb = self._peer_intro_callback
        if cb is not None:
            cb(peer, meta)

    # ------------------------------------------------------------------
    # Read-only state accessors (handy for tests / debugging)
    # ------------------------------------------------------------------

    @property
    def published_overlays(self) -> dict[bytes, str]:
        return dict(self._published)

    @property
    def known_offers(self) -> dict[bytes, set[bytes]]:
        return {h: set(mids) for h, mids in self._known_offers.items()}

    @property
    def published_manifests(self) -> dict[bytes, str]:
        return dict(self._published_manifests)

    @property
    def known_manifest_offers(self) -> dict[bytes, set[bytes]]:
        return {h: set(mids) for h, mids in self._known_manifest_offers.items()}

    @property
    def peer_meta(self) -> dict[bytes, PeerMeta]:
        """``peer.mid`` -> ``PeerMeta`` for every peer that has introduced itself."""
        return dict(self._peer_meta)

    @property
    def wallet_address(self) -> Optional[str]:
        """The wallet address this node advertises in its PEER_INTROs (None if unconfigured)."""
        return self._wallet_address
