"""SeedboxCommunity: the bootstrap overlay — signed-log admission, overlay
descriptor exchange, and content (file-bytes) transfer.

Wire protocol:

    CommunityJoinRequest/ResponsePayload                     admit-by-signed-log-entry
    OverlayOffer / OverlayRequest / OverlayDeliveryPayload   descriptor exchange
    PeerIntroPayload(wallet_address, known_overlays)         post-admission
    ContentRequest / ContentDeliveryPayload                  file bytes by content_id

Admission has no gatekeeper key: a joiner self-appends a signed donation_intent,
and membership is decided by every peer replaying the union of signed logs
(``agent.community_state.replay_community``). Descriptors and content are
addressed by sha1 — an overlay by sha1[:20] of its canonicalized markdown, a
file by sha1 of its bytes — and deliveries are re-hashed on receipt, so a peer
cannot smuggle in different bytes under the same id.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import msgpack
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver


# Mirror the signed_log pull-loop's HTTP access-log shape: one line per
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

# Cap on a single CONTENT_DELIVERY payload. Same 64 KiB envelope as
# overlay delivery — keeps wire-frame budgeting uniform. Content files
# bigger than this need chunking (out of scope for the current
# demo; the Creative Commons library serves <2 KiB text files).
MAX_CONTENT_BYTES = 64 * 1024


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


def content_id_for_bytes(data: bytes) -> bytes:
    """Full 20-byte sha1 of a file's bytes — the canonical content_id.

    The advertised magnet's btih hex MUST equal ``content_id_for_bytes(file).hex()``;
    that is what lets ``on_content_delivery`` self-verify the reply against
    the request without any out-of-band trust.
    """
    return hashlib.sha1(data).digest()


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
class ContentRequestPayload(VariablePayload):
    """Joiner-side request for a file by its content_id (sha1(bytes)).

    Mirrors ``OverlayRequestPayload`` shape, on a different msg_id so the
    receiver dispatches to the file-bytes handler — not the markdown one.
    """

    msg_id = 12
    format_list = ["20s"]
    names = ["content_id"]


@vp_compile
class ContentDeliveryPayload(VariablePayload):
    """Reply with the file bytes. The receiver verifies
    ``sha1(data) == content_id`` before resolving — exactly the same
    self-verifying property the overlay path uses for markdown."""

    msg_id = 13
    format_list = ["20s", "varlenH"]
    names = ["content_id", "data"]


@vp_compile
class CommunityJoinRequestPayload(VariablePayload):
    """Community admission: the joiner ships a JSON-serialised signed
    donation_intent entry. There is no gatekeeper key — the receiver replays
    the community-log state to decide accept/reject, and every other member
    reaches the same verdict by replaying the same signed logs."""

    msg_id = 10
    # signed_entry: utf-8 JSON of the signed-log self-entry the donor
    # appended to their own SignedAppendOnlyLog. The receiver re-verifies its
    # signature + identity binding and replays community state to decide.
    format_list = ["varlenH"]
    names = ["signed_entry"]


@vp_compile
class CommunityJoinResponsePayload(VariablePayload):
    """Reply to CommunityJoinRequest. ``reason`` is a short utf-8 string
    naming the failure mode for the LLM-facing log; empty on accept."""

    msg_id = 11
    format_list = ["?", "varlenH"]
    names = ["accepted", "reason"]


# Optional callbacks. ``OverlayOfferCallback`` fires when this node receives an
# OFFER for an overlay hash it doesn't already know. ``CommunityJoinCallback``
# decides accept/reject for the signed-log admission path (the community-state
# replay layer is the source of truth; the callback just plumbs it to the wire).
OverlayOfferCallback = Callable[[Peer, bytes], None]
PeerIntroCallback = Callable[[Peer, PeerMeta], None]
CommunityJoinCallback = Callable[[Peer, dict], tuple[bool, str]]


class SeedboxCommunity(Community, PeerObserver):
    """Bootstrap overlay: donation-gated admission + overlay-descriptor exchange."""

    community_id = b"openclaw_seedbox_v1\x00"  # exactly 20 bytes per IPv8 contract.

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        # OVERLAY bookkeeping.
        self._published: dict[bytes, str] = {}              # md_hash -> md_text we serve
        self._pending_fetches: dict[bytes, asyncio.Future[bytes]] = {}
        self._offer_callback: Optional[OverlayOfferCallback] = None

        # PEER_INTRO bookkeeping — populated on admission round-trip.
        self._wallet_address: Optional[str] = None        # set by configure()
        self._peer_meta: dict[bytes, PeerMeta] = {}        # peer.mid -> PeerMeta
        self._peer_intro_callback: Optional[PeerIntroCallback] = None

        # COMMUNITY_JOIN bookkeeping — the signed-log admission path.
        self._pending_community_joins: dict[bytes, asyncio.Future[tuple[bool, str]]] = {}
        self._community_join_callback: Optional[CommunityJoinCallback] = None

        # CONTENT exchange bookkeeping (file bytes by sha1 content_id).
        # The path-based store reads bytes on demand so a re-staged file
        # is picked up without re-publishing.
        self._content_store: dict[bytes, Path] = {}
        self._pending_content_fetches: dict[bytes, asyncio.Future[bytes]] = {}

        self.add_message_handler(OverlayOfferPayload, self.on_overlay_offer)
        self.add_message_handler(OverlayRequestPayload, self.on_overlay_request)
        self.add_message_handler(OverlayDeliveryPayload, self.on_overlay_delivery)
        self.add_message_handler(PeerIntroPayload, self.on_peer_intro)
        self.add_message_handler(CommunityJoinRequestPayload, self.on_community_join_request)
        self.add_message_handler(CommunityJoinResponsePayload, self.on_community_join_response)
        self.add_message_handler(ContentRequestPayload, self.on_content_request)
        self.add_message_handler(ContentDeliveryPayload, self.on_content_delivery)

    # ------------------------------------------------------------------
    # Configuration / wiring
    # ------------------------------------------------------------------

    def configure(
        self,
        *,
        offer_callback: Optional[OverlayOfferCallback] = None,
        wallet_address: Optional[str] = None,
        peer_intro_callback: Optional[PeerIntroCallback] = None,
        community_join_callback: Optional[CommunityJoinCallback] = None,
    ) -> None:
        """Wire optional collaborators after construction."""
        if offer_callback is not None:
            self._offer_callback = offer_callback
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
    # COMMUNITY_JOIN flow — admit-by-signed-log-entry (no gatekeeper key)
    # ------------------------------------------------------------------

    def request_community_join(
        self, gatekeeper: Peer, signed_entry: dict,
    ) -> asyncio.Future[tuple[bool, str]]:
        """Joiner-side: ship a JSON-serialised signed donation_intent entry.

        Returns a future resolving to ``(accepted, reason)``. The receiver does
        NOT hold a gatekeeper key — it caches the entry in its peer-log and
        replays community state to decide, and every member converges on the
        same verdict by replaying the same signed logs.
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

    def offer_overlay_to_all_peers(self) -> int:
        """Send OVERLAY_OFFER for every published overlay to every verified peer.

        Used right after an agent authors + publishes a new overlay so the
        whole fleet learns the new md_hash and can fetch it. Returns the count
        of (peer, overlay) offers sent. A node that has published nothing, or
        has no verified peers, sends nothing and returns 0.
        """
        hashes = list(self._published.keys())
        if not hashes:
            return 0
        sent = 0
        for peer in list(self.network.verified_peers):
            for md_hash in hashes:
                self.offer_overlay(peer, md_hash)
                sent += 1
        return sent

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
        # Verify the offering peer so a later fetch_overlay(peer, ...) — e.g. the
        # LLM adopting an offered overlay — can resolve it. An OFFER is an
        # explicit "you can ask me for this", so trusting the offerer is correct.
        self.network.add_verified_peer(peer)
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
        meta = PeerMeta(wallet_address=addr, known_overlays=tuple(overlays))
        self._peer_meta[peer.mid] = meta
        cb = self._peer_intro_callback
        if cb is not None:
            cb(peer, meta)

    # ------------------------------------------------------------------
    # CONTENT exchange (file bytes by sha1 content_id)
    # ------------------------------------------------------------------

    def publish_content(self, content_id: bytes, path: Path) -> bytes:
        """Make ``path``'s bytes available to peers that ask for ``content_id``.

        ``content_id`` MUST be ``sha1(path.read_bytes())`` — callers compute
        this once at boot so the file's advertised magnet btih equals the
        content_id (the self-verifying property the receiver relies on).
        Returns ``content_id`` for chained-call convenience.
        """
        if len(content_id) != 20:
            raise ValueError("content_id must be exactly 20 bytes")
        self._content_store[content_id] = Path(path)
        return content_id

    def fetch_content(self, peer: Peer, content_id: bytes) -> asyncio.Future[bytes]:
        """Fetcher-side: send CONTENT_REQUEST; resolve with the delivered bytes."""
        if len(content_id) != 20:
            raise ValueError("content_id must be exactly 20 bytes")
        loop = asyncio.get_event_loop()
        future: asyncio.Future[bytes] = loop.create_future()
        # Key by content_id, not peer.mid — first peer with the bytes wins
        # (same pattern as fetch_overlay).
        self._pending_content_fetches[content_id] = future
        _log_wire("send", "ContentRequest", peer, content_id=content_id.hex()[:16])
        self.ez_send(peer, ContentRequestPayload(content_id))
        return future

    @lazy_wrapper(ContentRequestPayload)
    def on_content_request(self, peer: Peer, payload: ContentRequestPayload) -> None:
        _log_wire("recv", "ContentRequest", peer, content_id=payload.content_id.hex()[:16])
        path = self._content_store.get(payload.content_id)
        if path is None or not path.is_file():
            return  # silently ignore; requester times out
        try:
            data = path.read_bytes()
        except OSError as exc:
            _wire_logger.warning("content read failed for %s: %s", path, exc)
            return
        if len(data) > MAX_CONTENT_BYTES:
            _wire_logger.warning(
                "content %s exceeds %d-byte cap (%d); refusing to send",
                path.name, MAX_CONTENT_BYTES, len(data),
            )
            return
        # Defence in depth: only ship bytes whose hash matches what was
        # requested. Catches a stale store entry pointing at a swapped file.
        if hashlib.sha1(data).digest() != payload.content_id:
            _wire_logger.warning(
                "content_store path %s no longer hashes to %s; refusing to send",
                path, payload.content_id.hex()[:16],
            )
            return
        _log_wire(
            "send", "ContentDelivery", peer,
            content_id=payload.content_id.hex()[:16], bytes=len(data),
        )
        self.ez_send(peer, ContentDeliveryPayload(payload.content_id, data))

    @lazy_wrapper(ContentDeliveryPayload)
    def on_content_delivery(self, peer: Peer, payload: ContentDeliveryPayload) -> None:
        _log_wire(
            "recv", "ContentDelivery", peer,
            content_id=payload.content_id.hex()[:16], bytes=len(payload.data),
        )
        if len(payload.data) > MAX_CONTENT_BYTES:
            return
        # Self-verifying: refuse to resolve unless the bytes hash to the
        # exact content_id we asked for. A malicious peer cannot smuggle in
        # different bytes under the same id.
        if hashlib.sha1(payload.data).digest() != payload.content_id:
            return
        future = self._pending_content_fetches.pop(payload.content_id, None)
        if future is not None and not future.done():
            future.set_result(payload.data)

    # ------------------------------------------------------------------
    # Read-only state accessors (handy for tests / debugging)
    # ------------------------------------------------------------------

    @property
    def peer_meta(self) -> dict[bytes, PeerMeta]:
        """``peer.mid`` -> ``PeerMeta`` for every peer that has introduced itself."""
        return dict(self._peer_meta)

    @property
    def wallet_address(self) -> Optional[str]:
        """The wallet address this node advertises in its PEER_INTROs (None if unconfigured)."""
        return self._wallet_address

    @property
    def published_content(self) -> dict[bytes, Path]:
        """``content_id`` (20-byte sha1) -> on-disk path we serve."""
        return dict(self._content_store)
