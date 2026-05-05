"""OpenClaw PoC Community: identity announcements, peer registry, and re-announcement."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer

from shared.logging import get_logger

_log = get_logger("claw_poc")

ANNOUNCE_INTERVAL = 60  # seconds



@dataclass
class PeerIdentityRecord:
    """In-memory record of a peer's OpenClaw identity announcement."""
    mid: bytes                       # IPv8 member ID (20 bytes)
    identity_hash: bytes             # SHA-256 (32 bytes)
    public_key: bytes                # serialized IPv8 public key
    network: str                     # network name (MAINNET, TESTNET, etc.)
    last_seen: int                   # Unix epoch seconds


@vp_compile
class IdentityAnnouncementPayload(VariablePayload):
    """OpenClaw identity announcement packet."""
    msg_id = 1
    format_list = ["32s", "varlenH", "varlenH", "Q"]
    names = ["identity_hash", "public_key", "network", "timestamp"]


class ClawPoCCommunity(Community):
    """OpenClaw PoC Community: maintains local identity and peer identity registry.

    After wiring with `OpenClawIdentity`, broadcasts identity announcements to all peers
    and maintains a local registry of peer identities received over IPv8.
    """

    # IPv8 expects a 22-byte prefix total; with version + sentinel byte, community_id must be 20 bytes.
    community_id = b"openclawpocv1agent01"

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self._openclaw_identity: Any | None = None
        self._peer_identities: dict[bytes, PeerIdentityRecord] = {}
        self.add_message_handler(IdentityAnnouncementPayload, self._on_identity_announcement)

    def wire(self, *, openclaw_identity: Any) -> None:
        """Inject the OpenClaw identity (post-construction, before start)."""
        self._openclaw_identity = openclaw_identity

    def started(self) -> None:
        """IPv8 lifecycle hook: log, announce identity, schedule periodic re-announcement."""
        _log.info("ClawPoCCommunity started; my mid=%s", getattr(self.my_peer, "mid", None))
        if self._openclaw_identity is not None:
            self.announce_identity()
            self.register_task(
                "periodic_announce",
                self._broadcast_identity,
                interval=ANNOUNCE_INTERVAL,
                delay=ANNOUNCE_INTERVAL,
            )

    def peer_added(self, peer: Peer) -> None:
        """Called by IPv8 when a new peer joins. Send them our identity announcement."""
        super().peer_added(peer)
        self._send_identity_announcement(peer)

    def announce_identity(self) -> None:
        """Log the local identity and broadcast to all current peers."""
        if self._openclaw_identity is None:
            _log.warning("No OpenClaw identity wired into community")
            return
        try:
            iid = self._openclaw_identity.get_identity_hash()
            pub = self._openclaw_identity.serialized_public_key.hex()
            _log.info("OpenClaw Identity: %s", iid)
            _log.info("IPv8 serialized pubkey: %s", pub)
        except Exception as exc:
            _log.exception("Failed to read identity: %s", exc)
        self._broadcast_identity()

    def _broadcast_identity(self) -> None:
        """Send identity announcement to all connected peers."""
        for peer in self.get_peers():
            self._send_identity_announcement(peer)

    def _send_identity_announcement(self, peer: Peer) -> None:
        """Send an identity announcement to a single peer."""
        if self._openclaw_identity is None:
            _log.warning("Cannot announce identity: no openclaw_identity wired")
            return
        try:
            payload = IdentityAnnouncementPayload(
                identity_hash=self._openclaw_identity.identity_hash_bytes,
                public_key=self._openclaw_identity.serialized_public_key,
                network=self._openclaw_identity.network,
                timestamp=int(time.time()),
            )
            self.ez_send(peer, payload)
        except Exception as exc:
            _log.exception("Failed to send identity announcement to peer %s: %s", peer.mid.hex(), exc)

    @lazy_wrapper(IdentityAnnouncementPayload)
    def _on_identity_announcement(self, peer: Peer, payload: IdentityAnnouncementPayload) -> None:
        """Handle an incoming identity announcement from a peer."""
        # Validate identity_hash length
        if len(payload.identity_hash) != 32:
            _log.debug("Dropping identity announcement from %s: invalid hash length %d", peer.mid.hex(), len(payload.identity_hash))
            return
        # Validate network is non-empty
        if not payload.network or not isinstance(payload.network, str):
            _log.debug("Dropping identity announcement from %s: invalid network field", peer.mid.hex())
            return
        # Store the identity record
        record = PeerIdentityRecord(
            mid=peer.mid,
            identity_hash=payload.identity_hash,
            public_key=payload.public_key,
            network=payload.network,
            last_seen=payload.timestamp,
        )
        self._peer_identities[peer.mid] = record
        _log.info(
            "peer_identity_received mid=%s identity_hash=%s network=%s",
            peer.mid.hex(),
            payload.identity_hash.hex(),
            payload.network,
        )

    @property
    def peer_identities(self) -> dict[bytes, PeerIdentityRecord]:
        """Return a shallow copy of the current peer identity registry."""
        return dict(self._peer_identities)

    def get_peer_identity(self, mid: bytes) -> PeerIdentityRecord | None:
        """Retrieve the identity record for a peer by its IPv8 mid, or None if unknown."""
        return self._peer_identities.get(mid)










