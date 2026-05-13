"""SeedboxCommunity: admit-by-donation + overlay-descriptor distribution.

Wire protocol:

    JoinRequestPayload(donation_txid: bytes)        joiner -> gatekeeper
    JoinResponsePayload(accepted: bool)             gatekeeper -> joiner
    OverlayOfferPayload(md_hash: 20 bytes)          peer -> peer
    OverlayRequestPayload(md_hash: 20 bytes)        peer -> peer
    OverlayDeliveryPayload(md_hash, md_text)        peer -> peer

Joiner-side helpers:

    ``request_join(gatekeeper, donation_txid) -> asyncio.Future[bool]``
        send JOIN_REQUEST + return a future for the decision.

    ``fetch_overlay(peer, md_hash) -> asyncio.Future[bytes]``
        send OVERLAY_REQUEST + return a future for the md_text bytes.

Publisher-side:

    ``publish_overlay(md_text)`` registers an overlay-descriptor that
    this node is willing to serve via OVERLAY_DELIVERY when peers ask
    for it (looked up by sha1 of the canonicalized bytes).
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Callable, Optional

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver

from replication.verification.donation_verifier import DonationVerifier


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


# Optional callback signature: invoked when this node receives an OFFER
# for a hash it doesn't already know about.
OverlayOfferCallback = Callable[[Peer, bytes], None]


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

        self.add_message_handler(JoinRequestPayload, self.on_join_request)
        self.add_message_handler(JoinResponsePayload, self.on_join_response)
        self.add_message_handler(OverlayOfferPayload, self.on_overlay_offer)
        self.add_message_handler(OverlayRequestPayload, self.on_overlay_request)
        self.add_message_handler(OverlayDeliveryPayload, self.on_overlay_delivery)

    # ------------------------------------------------------------------
    # Configuration / wiring
    # ------------------------------------------------------------------

    def configure(
        self,
        *,
        verifier: Optional[DonationVerifier] = None,
        offer_callback: Optional[OverlayOfferCallback] = None,
    ) -> None:
        """Wire optional collaborators after construction."""
        if verifier is not None:
            self._verifier = verifier
        if offer_callback is not None:
            self._offer_callback = offer_callback

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
        self.ez_send(gatekeeper, JoinRequestPayload(donation_txid))
        return future

    @lazy_wrapper(JoinRequestPayload)
    def on_join_request(self, peer: Peer, payload: JoinRequestPayload) -> None:
        if self._verifier is None:
            self.ez_send(peer, JoinResponsePayload(False))
            return
        result = self._verifier.verify(payload.donation_txid.hex())
        if result.accepted:
            self.network.add_verified_peer(peer)
        self.ez_send(peer, JoinResponsePayload(result.accepted))

    @lazy_wrapper(JoinResponsePayload)
    def on_join_response(self, peer: Peer, payload: JoinResponsePayload) -> None:
        future = self._pending_joins.pop(peer.mid, None)
        if future is not None and not future.done():
            future.set_result(payload.accepted)

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
        self.ez_send(peer, OverlayRequestPayload(md_hash))
        return future

    @lazy_wrapper(OverlayOfferPayload)
    def on_overlay_offer(self, peer: Peer, payload: OverlayOfferPayload) -> None:
        self._known_offers.setdefault(payload.md_hash, set()).add(peer.mid)
        cb = self._offer_callback
        if cb is not None:
            cb(peer, payload.md_hash)

    @lazy_wrapper(OverlayRequestPayload)
    def on_overlay_request(self, peer: Peer, payload: OverlayRequestPayload) -> None:
        md_text = self._published.get(payload.md_hash)
        if md_text is None:
            return  # silently ignore; requester times out at its end
        body = md_text.encode("utf-8")
        if len(body) > MAX_OVERLAY_BYTES:
            return  # we never publish anything that big; defensive drop
        self.ez_send(peer, OverlayDeliveryPayload(payload.md_hash, body))

    @lazy_wrapper(OverlayDeliveryPayload)
    def on_overlay_delivery(self, peer: Peer, payload: OverlayDeliveryPayload) -> None:
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
    # Read-only state accessors (handy for tests / debugging)
    # ------------------------------------------------------------------

    @property
    def published_overlays(self) -> dict[bytes, str]:
        return dict(self._published)

    @property
    def known_offers(self) -> dict[bytes, set[bytes]]:
        return {h: set(mids) for h, mids in self._known_offers.items()}
