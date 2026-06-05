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
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
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


@dataclass(frozen=True)
class CommunityLineageConfig:
    """Opt-in peer-lineage admission policy for SeedboxCommunity."""

    enabled: bool = False
    required: bool = False
    trusted_roots: tuple[dict[str, str], ...] = ()
    min_anchor_confirmations: int = 0
    accepted_capabilities: tuple[str, ...] = ()
    cache_path: Optional[Path] = None
    challenge_timeout_s: float = 10.0


@dataclass
class _PendingLineageChallenge:
    future: asyncio.Future[dict]
    expires_at: float
    on_decision: Optional[Callable[[bool, dict], None]] = None


# Cap on a single OVERLAY_DELIVERY payload — protects against a peer
# trying to flood us with arbitrarily large markdown blobs.
MAX_OVERLAY_BYTES = 64 * 1024
MAX_LINEAGE_PROOF_BYTES = 256 * 1024

LINEAGE_CHALLENGE_SIGNATURE_DOMAIN = b"DEAI_IPV8_LINEAGE_CHALLENGE_V1\x00"
LINEAGE_PROOF_SIGNATURE_DOMAIN = b"DEAI_IPV8_LINEAGE_PROOF_V1\x00"


def lineage_challenge_signing_payload(nonce: bytes) -> bytes:
    return LINEAGE_CHALLENGE_SIGNATURE_DOMAIN + bytes(nonce)


def lineage_proof_signing_payload(nonce: bytes, proof_json: bytes) -> bytes:
    return LINEAGE_PROOF_SIGNATURE_DOMAIN + bytes(nonce) + bytes(proof_json)


def _verify_peer_signature(peer: Peer, payload: bytes, signature: bytes) -> bool:
    try:
        return bool(peer.public_key.verify(bytes(signature), bytes(payload)))
    except Exception:
        return False


def _peer_operational_pubkey_hexes(peer: Peer) -> set[str]:
    """Return raw and serialized public-key hex forms accepted in lineage certs."""

    values: set[str] = set()
    try:
        public_bin = peer.public_key.key_to_bin()
        values.add(public_bin.hex())
        if public_bin.startswith(b"LibNaCLPK:") and len(public_bin) >= 74:
            values.add(public_bin[42:74].hex())
        elif len(public_bin) == 32:
            values.add(public_bin.hex())
    except Exception:
        pass
    return values


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


@vp_compile
class LineageChallengePayload(VariablePayload):
    """Signed lineage challenge. The 32-byte nonce is one-use and fresh."""

    msg_id = 12
    format_list = ["32s", "varlenH"]
    names = ["nonce", "signature"]


@vp_compile
class LineageProofPayload(VariablePayload):
    """Signed response carrying a JSON-serialized LineageProof."""

    msg_id = 13
    format_list = ["32s", "varlenH", "varlenH"]
    names = ["nonce", "proof_json", "signature"]


# Optional callback signatures: invoked when this node receives an OFFER
# for a hash it doesn't already know about.
OverlayOfferCallback = Callable[[Peer, bytes], None]
ManifestOfferCallback = Callable[[Peer, bytes], None]
PeerIntroCallback = Callable[[Peer, PeerMeta], None]
LineageProofProvider = Callable[[], Optional[dict]]
LineageStatusCallback = Callable[[Peer, dict], None]

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

        self._lineage_config = CommunityLineageConfig()
        self._lineage_proof_provider: Optional[LineageProofProvider] = None
        self._lineage_status_callback: Optional[LineageStatusCallback] = None
        self._pending_lineage_challenges: dict[tuple[bytes, bytes], _PendingLineageChallenge] = {}
        self._seen_inbound_lineage_challenges: set[tuple[bytes, bytes]] = set()
        self._lineage_peer_status: dict[bytes, dict] = {}

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
        self.add_message_handler(LineageChallengePayload, self.on_lineage_challenge)
        self.add_message_handler(LineageProofPayload, self.on_lineage_proof)

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
        lineage_config: Optional[CommunityLineageConfig] = None,
        lineage_proof_provider: Optional[LineageProofProvider] = None,
        lineage_status_callback: Optional[LineageStatusCallback] = None,
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
        if lineage_config is not None:
            self._lineage_config = lineage_config
        if lineage_proof_provider is not None:
            self._lineage_proof_provider = lineage_proof_provider
        if lineage_status_callback is not None:
            self._lineage_status_callback = lineage_status_callback

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, peer: Peer) -> None:
        pass

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    # ------------------------------------------------------------------
    # LINEAGE challenge / response
    # ------------------------------------------------------------------

    def _sign_lineage_payload(self, payload: bytes) -> bytes:
        key = getattr(self.my_peer, "key", None)
        if key is not None and hasattr(key, "signature"):
            return key.signature(payload)
        raise RuntimeError("SeedboxCommunity peer key does not support signatures")

    def _lineage_enabled(self) -> bool:
        return bool(self._lineage_config.enabled)

    def _lineage_required(self) -> bool:
        return bool(self._lineage_config.enabled and self._lineage_config.required)

    def _record_lineage_status(self, peer: Peer, status: dict) -> None:
        stored = dict(status)
        stored.setdefault("peer_mid", peer.mid.hex())
        self._lineage_peer_status[peer.mid] = stored
        cb = self._lineage_status_callback
        if cb is not None:
            cb(peer, dict(stored))

    def _lineage_status(
        self,
        *,
        ok: bool,
        status: str,
        nonce: bytes | None = None,
        errors: list[str] | None = None,
        result: dict | None = None,
    ) -> dict:
        out = dict(result or {})
        out.update({
            "ok": bool(ok),
            "status": status,
            "nonce": nonce.hex() if nonce else "",
            "errors": list(errors or out.get("errors", [])),
        })
        return out

    def _challenge_peer_for_lineage(
        self,
        peer: Peer,
        *,
        on_decision: Optional[Callable[[bool, dict], None]] = None,
    ) -> asyncio.Future[dict]:
        loop = asyncio.get_event_loop()
        nonce = os.urandom(32)
        future: asyncio.Future[dict] = loop.create_future()
        expires_at = time.monotonic() + max(0.1, float(self._lineage_config.challenge_timeout_s))
        self._pending_lineage_challenges[(peer.mid, nonce)] = _PendingLineageChallenge(
            future=future,
            expires_at=expires_at,
            on_decision=on_decision,
        )
        signature = self._sign_lineage_payload(lineage_challenge_signing_payload(nonce))
        _log_wire("send", "LineageChallenge", peer, nonce=nonce.hex()[:16])
        self.ez_send(peer, LineageChallengePayload(nonce, signature))
        loop.create_task(self._lineage_timeout(peer, nonce))
        return future

    async def _lineage_timeout(self, peer: Peer, nonce: bytes) -> None:
        await asyncio.sleep(max(0.1, float(self._lineage_config.challenge_timeout_s)))
        pending = self._pending_lineage_challenges.pop((peer.mid, nonce), None)
        if pending is None:
            return
        result = self._lineage_status(
            ok=False,
            status="missing",
            nonce=nonce,
            errors=["lineage proof was not received before challenge timeout"],
        )
        self._record_lineage_status(peer, result)
        if not pending.future.done():
            pending.future.set_result(result)
        if pending.on_decision is not None:
            pending.on_decision(False, result)

    def request_lineage(self, peer: Peer) -> asyncio.Future[dict]:
        """Send a signed lineage challenge and resolve with peer proof status."""

        if not self._lineage_enabled():
            loop = asyncio.get_event_loop()
            future: asyncio.Future[dict] = loop.create_future()
            future.set_result(self._lineage_status(ok=True, status="disabled"))
            return future
        return self._challenge_peer_for_lineage(peer)

    def _admit_or_challenge_for_lineage(
        self,
        peer: Peer,
        *,
        on_accept: Callable[[], None],
        on_reject: Callable[[dict], None],
    ) -> None:
        if not self._lineage_enabled():
            on_accept()
            return
        if not self._lineage_required():
            on_accept()
            self._challenge_peer_for_lineage(peer)
            return
        current = self._lineage_peer_status.get(peer.mid)
        if current is not None and current.get("ok") is True:
            on_accept()
            return

        def _finish(ok: bool, result: dict) -> None:
            if ok:
                on_accept()
            else:
                on_reject(result)

        self._challenge_peer_for_lineage(peer, on_decision=_finish)

    def _verify_received_lineage_proof(
        self,
        peer: Peer,
        nonce: bytes,
        proof_json: bytes,
    ) -> dict:
        if not proof_json:
            return self._lineage_status(
                ok=False,
                status="missing",
                nonce=nonce,
                errors=["lineage proof missing"],
            )
        if len(proof_json) > MAX_LINEAGE_PROOF_BYTES:
            return self._lineage_status(
                ok=False,
                status="invalid",
                nonce=nonce,
                errors=["lineage proof exceeds maximum size"],
            )
        try:
            raw = json.loads(proof_json.decode("utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("proof JSON must be an object")
            from identity.lineage.models import LineageProof
            from identity.lineage.verifier import verify_lineage_proof

            proof = LineageProof.from_dict(raw)
        except Exception as exc:
            return self._lineage_status(
                ok=False,
                status="invalid",
                nonce=nonce,
                errors=[f"lineage proof decode failed:{type(exc).__name__}: {exc}"],
            )

        operational_pubkey = proof.leaf_certificate.child_operational_pubkey.strip().lower()
        peer_pubkeys = _peer_operational_pubkey_hexes(peer)
        if operational_pubkey and operational_pubkey not in peer_pubkeys:
            return self._lineage_status(
                ok=False,
                status="invalid",
                nonce=nonce,
                errors=["lineage proof operational pubkey does not match IPv8 peer"],
            )

        capabilities: tuple[str | None, ...]
        if self._lineage_config.accepted_capabilities:
            capabilities = tuple(self._lineage_config.accepted_capabilities)
        else:
            capabilities = (None,)

        last_result = None
        for capability in capabilities:
            result = verify_lineage_proof(
                proof,
                trusted_roots=[dict(root) for root in self._lineage_config.trusted_roots],
                requested_capability=capability,
                min_confirmations=int(self._lineage_config.min_anchor_confirmations),
                cache=self._lineage_config.cache_path,
            )
            result_dict = result.to_dict()
            result_dict["requested_capability"] = capability or ""
            if result.ok:
                return self._lineage_status(
                    ok=True,
                    status=result.status,
                    nonce=nonce,
                    result=result_dict,
                )
            last_result = result_dict

        errors = list((last_result or {}).get("errors", []))
        if self._lineage_config.accepted_capabilities:
            errors.append("lineage proof does not satisfy accepted capabilities")
        return self._lineage_status(
            ok=False,
            status=str((last_result or {}).get("status", "invalid")),
            nonce=nonce,
            errors=errors,
            result=last_result,
        )

    @lazy_wrapper(LineageChallengePayload)
    def on_lineage_challenge(self, peer: Peer, payload: LineageChallengePayload) -> None:
        nonce = bytes(payload.nonce)
        _log_wire("recv", "LineageChallenge", peer, nonce=nonce.hex()[:16])
        if not _verify_peer_signature(
            peer,
            lineage_challenge_signing_payload(nonce),
            payload.signature,
        ):
            self._record_lineage_status(peer, self._lineage_status(
                ok=False,
                status="invalid",
                nonce=nonce,
                errors=["lineage challenge signature is invalid"],
            ))
            return
        seen_key = (peer.mid, nonce)
        if seen_key in self._seen_inbound_lineage_challenges:
            self._record_lineage_status(peer, self._lineage_status(
                ok=False,
                status="replay",
                nonce=nonce,
                errors=["lineage challenge nonce was replayed"],
            ))
            return
        self._seen_inbound_lineage_challenges.add(seen_key)
        if len(self._seen_inbound_lineage_challenges) > 2048:
            self._seen_inbound_lineage_challenges.pop()

        proof_json = b""
        provider = self._lineage_proof_provider
        if provider is not None:
            try:
                proof = provider()
                if proof is not None:
                    proof_json = json.dumps(
                        proof,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
            except Exception:
                proof_json = b""
        signature = self._sign_lineage_payload(
            lineage_proof_signing_payload(nonce, proof_json)
        )
        _log_wire(
            "send",
            "LineageProof",
            peer,
            nonce=nonce.hex()[:16],
            proof_bytes=len(proof_json),
        )
        self.ez_send(peer, LineageProofPayload(nonce, proof_json, signature))

    @lazy_wrapper(LineageProofPayload)
    def on_lineage_proof(self, peer: Peer, payload: LineageProofPayload) -> None:
        nonce = bytes(payload.nonce)
        proof_json = bytes(payload.proof_json)
        _log_wire(
            "recv",
            "LineageProof",
            peer,
            nonce=nonce.hex()[:16],
            proof_bytes=len(proof_json),
        )
        pending = self._pending_lineage_challenges.pop((peer.mid, nonce), None)
        if pending is None:
            self._record_lineage_status(peer, self._lineage_status(
                ok=False,
                status="replay",
                nonce=nonce,
                errors=["lineage proof nonce is stale, replayed, or unsolicited"],
            ))
            return
        if time.monotonic() > pending.expires_at:
            result = self._lineage_status(
                ok=False,
                status="replay",
                nonce=nonce,
                errors=["lineage proof nonce expired"],
            )
        elif not _verify_peer_signature(
            peer,
            lineage_proof_signing_payload(nonce, proof_json),
            payload.signature,
        ):
            result = self._lineage_status(
                ok=False,
                status="invalid",
                nonce=nonce,
                errors=["lineage proof signature is invalid"],
            )
        else:
            result = self._verify_received_lineage_proof(peer, nonce, proof_json)

        self._record_lineage_status(peer, result)
        if not pending.future.done():
            pending.future.set_result(result)
        if pending.on_decision is not None:
            pending.on_decision(bool(result.get("ok")), result)

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
        if not result.accepted:
            _log_wire("send", "JoinResponse", peer, accepted=False)
            self.ez_send(peer, JoinResponsePayload(False))
            return

        def _accept() -> None:
            self.network.add_verified_peer(peer)
            _log_wire("send", "JoinResponse", peer, accepted=True)
            self.ez_send(peer, JoinResponsePayload(True))
            self._send_peer_intro(peer)

        def _reject(lineage_result: dict) -> None:
            _log_wire(
                "send",
                "JoinResponse",
                peer,
                accepted=False,
                lineage_status=lineage_result.get("status", "invalid"),
            )
            self.ez_send(peer, JoinResponsePayload(False))

        self._admit_or_challenge_for_lineage(peer, on_accept=_accept, on_reject=_reject)

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
        if not accepted:
            _log_wire(
                "send", "CommunityJoinResponse", peer,
                accepted=False, reason=(reason or "")[:60],
            )
            self.ez_send(
                peer,
                CommunityJoinResponsePayload(False, (reason or "").encode("utf-8")),
            )
            return

        def _accept() -> None:
            self.network.add_verified_peer(peer)
            _log_wire(
                "send", "CommunityJoinResponse", peer,
                accepted=True, reason="",
            )
            self.ez_send(peer, CommunityJoinResponsePayload(True, b""))
            self._send_peer_intro(peer)

        def _reject(lineage_result: dict) -> None:
            lineage_reason = f"lineage_{lineage_result.get('status', 'invalid')}"
            _log_wire(
                "send", "CommunityJoinResponse", peer,
                accepted=False, reason=lineage_reason,
            )
            self.ez_send(
                peer,
                CommunityJoinResponsePayload(False, lineage_reason.encode("utf-8")),
            )

        self._admit_or_challenge_for_lineage(peer, on_accept=_accept, on_reject=_reject)

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
        meta = PeerMeta(wallet_address=addr, known_overlays=tuple(overlays))

        def _accept() -> None:
            self.network.add_verified_peer(peer)
            self._peer_meta[peer.mid] = meta
            cb = self._peer_intro_callback
            if cb is not None:
                cb(peer, meta)

        def _reject(_lineage_result: dict) -> None:
            return

        self._admit_or_challenge_for_lineage(peer, on_accept=_accept, on_reject=_reject)

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
    def lineage_peer_status(self) -> dict[bytes, dict]:
        """``peer.mid`` -> latest lineage challenge/verification status."""
        return {mid: dict(status) for mid, status in self._lineage_peer_status.items()}

    @property
    def wallet_address(self) -> Optional[str]:
        """The wallet address this node advertises in its PEER_INTROs (None if unconfigured)."""
        return self._wallet_address
