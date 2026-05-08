"""TrustroomCommunity: the IPv8 Community subclass at the centre of the sub-project."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from enum import IntEnum
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile

from communication.admission.codec import unpack_presentation
from communication.payload.application_message import unpack_application_message
from communication.replay.nonce_cache import NonceCache
from communication.replay.timestamp_check import is_within_skew
from shared.envelopes import WireFrame
from shared.errors import PayloadInvalid
from shared.ids import AgentId, RoomId
from shared.logging import get_logger
from shared.stake import StakeOp

_log = get_logger("trustroom_community")

if TYPE_CHECKING:
    from identity.agent_identity import AgentIdentity
    from communication.admission.join_protocol import AdmissionGate
    from communication.payload.application_message import PayloadRouter
    from communication.trustroom.policy import AdmissionContext, AdmissionPolicy
    from communication.trustroom.state import TrustroomState
    from stake.oracle import StakeOracle


# --- VariablePayloads ----------------------------------------------------------
# IPv8 frames + signs each VariablePayload via ez_send. One subclass per MsgId.
# Field names are positional in `format_list`.

@vp_compile
class JoinRequestPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenH", "varlenH"]
    names = ["room_id", "presentation"]


@vp_compile
class JoinResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["varlenH", "?", "varlenH"]
    names = ["room_id", "accepted", "host_app_pubkey"]
    # `host_app_pubkey` is the host's 32-byte AppSigningKey verify-key, sent
    # so the joiner can pin it for future host→joiner WireFrame verification.
    # Empty bytes when accepted is False.


@vp_compile
class ApplicationMessagePayload(VariablePayload):
    msg_id = 3
    format_list = ["varlenH"]
    names = ["frame"]  # serialized WireFrame bytes


@vp_compile
class RoomAdvertisementPayload(VariablePayload):
    msg_id = 4
    format_list = ["varlenH"]
    names = ["advertisement"]


@vp_compile
class StakeOpPayload(VariablePayload):
    msg_id = 5
    format_list = ["varlenH"]
    names = ["op"]  # serialized StakeOp.to_bytes()


def _ed25519_verify(pubkey: bytes, data: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


class TrustroomCommunity(Community):
    """Layer 2 IPv8 Community subclass — the network face of every Trustroom."""

    community_id = b"openclawtrustroomv1\x00"  # 20 bytes per IPv8 contract

    class MsgId(IntEnum):
        JOIN_REQUEST = 1
        JOIN_RESPONSE = 2
        APPLICATION = 3
        ROOM_ADVERTISEMENT = 4
        STAKE_OP = 5

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self._identity: "AgentIdentity | None" = None
        self._admission: "AdmissionGate | None" = None
        self._payload_router: "PayloadRouter | None" = None
        self._trustroom_state: "TrustroomState | None" = None
        self._oracle: "StakeOracle | None" = None
        self._join_nonces = NonceCache()
        self._app_nonces: dict[tuple[bytes, bytes], NonceCache] = {}
        # Future result is (accepted, host_app_pubkey); pubkey is b"" when rejected.
        self._pending_joins: dict[bytes, asyncio.Future[tuple[bool, bytes]]] = {}

        self.add_message_handler(JoinRequestPayload, self.on_join_request)
        self.add_message_handler(JoinResponsePayload, self.on_join_response)
        self.add_message_handler(ApplicationMessagePayload, self.on_application_message)
        self.add_message_handler(RoomAdvertisementPayload, self.on_room_advertisement)
        self.add_message_handler(StakeOpPayload, self.on_stake_op)

    def wire(
        self,
        *,
        identity: "AgentIdentity",
        admission: "AdmissionGate",
        payload_router: "PayloadRouter",
        trustroom_state: "TrustroomState",
        oracle: "StakeOracle",
    ) -> None:
        """Inject dependencies post-construction.

        The IPv8 service constructs Community subclasses from its config dict, so
        higher-level wiring happens once the overlay is loaded.
        """
        self._identity = identity
        self._admission = admission
        self._payload_router = payload_router
        self._trustroom_state = trustroom_state
        self._oracle = oracle
        _log.info(
            "community_wired",
            agent_id=str(identity.agent_id),
            network=identity.network,
            peer_mid=self.my_peer.mid.hex() if self.my_peer else None,
        )

    def started(self) -> None:
        """IPv8 lifecycle hook fired by the on_start config entry."""
        _log.info("community_started", peer_mid=self.my_peer.mid.hex())

    # --- public API consumed by AgentChannel --------------------------------

    def create_room(
        self, policy: "AdmissionPolicy", *, policy_descriptor: str = ""
    ) -> RoomId:
        if self._identity is None or self._trustroom_state is None:
            raise RuntimeError("TrustroomCommunity not wired before create_room")
        room_id = RoomId.fresh()
        descriptor = policy_descriptor or type(policy).__name__
        self._trustroom_state.create(
            room_id,
            host=self._identity.agent_id,
            host_app_pubkey=self._identity.app.pubkey,
            policy_descriptor=descriptor,
        )
        _log.debug(
            "create_room_state_initialised",
            room_id=room_id.to_bytes().hex(),
            host=str(self._identity.agent_id),
            policy=descriptor,
        )
        return room_id

    async def send_join_request(
        self,
        host_peer: Any,
        room_id: RoomId,
        presentation_bytes: bytes,
    ) -> tuple[bool, bytes]:
        """Send a JOIN_REQUEST and await the host's JOIN_RESPONSE (5 s timeout).

        Returns ``(accepted, host_app_pubkey)``. The pubkey is the host's
        AppSigningKey verify-key (32 bytes) when accepted; empty bytes
        otherwise.
        """
        loop = asyncio.get_event_loop()
        future: asyncio.Future[tuple[bool, bytes]] = loop.create_future()
        self._pending_joins[room_id.to_bytes()] = future
        _log.info(
            "join_request_sent",
            room_id=room_id.to_bytes().hex(),
            presentation_bytes=len(presentation_bytes),
            host_mid=host_peer.mid.hex() if hasattr(host_peer, "mid") else None,
        )
        self.ez_send(
            host_peer,
            JoinRequestPayload(room_id=room_id.to_bytes(), presentation=presentation_bytes),
        )
        try:
            accepted, host_app_pubkey = await asyncio.wait_for(future, timeout=5.0)
            _log.debug(
                "join_request_future_resolved",
                room_id=room_id.to_bytes().hex(),
                accepted=accepted,
                host_app_pubkey_bytes=len(host_app_pubkey),
            )
            return accepted, host_app_pubkey
        except asyncio.TimeoutError:
            _log.info(
                "join_request_timeout",
                room_id=room_id.to_bytes().hex(),
                timeout_seconds=5.0,
            )
            raise
        finally:
            self._pending_joins.pop(room_id.to_bytes(), None)

    def leave_room(self, room_id: RoomId) -> None:
        if self._trustroom_state is not None:
            self._trustroom_state.remove(room_id)
        _log.info("room_state_removed", room_id=room_id.to_bytes().hex())

    async def send_application(self, peer: Any, frame_bytes: bytes) -> None:
        """Wire a signed WireFrame to ``peer`` via IPv8."""
        _log.info(
            "application_sent",
            frame_bytes=len(frame_bytes),
            target_mid=peer.mid.hex() if hasattr(peer, "mid") else None,
        )
        self.ez_send(peer, ApplicationMessagePayload(frame=frame_bytes))

    async def send_stake_op(self, peer: Any, op_bytes: bytes) -> None:
        """Forward a signed ``StakeOp`` to ``peer`` so they can apply it locally."""
        _log.info(
            "stake_op_sent",
            op_bytes=len(op_bytes),
            target_mid=peer.mid.hex() if hasattr(peer, "mid") else None,
        )
        self.ez_send(peer, StakeOpPayload(op=op_bytes))

    def members(self, room_id: RoomId) -> list[AgentId]:
        if self._trustroom_state is None:
            return []
        return self._trustroom_state.members(room_id)

    # --- IPv8 message handlers ---------------------------------------------

    @lazy_wrapper(JoinRequestPayload)
    def on_join_request(self, peer: Any, payload: JoinRequestPayload) -> None:
        room_id_bytes = bytes(payload.room_id)
        _log.info(
            "join_request_received",
            room_id=room_id_bytes.hex(),
            presentation_bytes=len(payload.presentation),
            from_mid=peer.mid.hex() if hasattr(peer, "mid") else None,
        )

        if self._identity is None or self._admission is None or self._trustroom_state is None:
            _log.warning("on_join_request_dropped", reason="not_wired")
            return

        try:
            room_id = RoomId(room_id_bytes)
        except ValueError:
            _log.info("on_join_request_rejected", reason="bad_room_id")
            return self._reject(peer, room_id_bytes, "malformed room_id")

        # Reject join requests for rooms we are not hosting.
        if room_id not in self._trustroom_state:
            _log.info("on_join_request_rejected", room_id=room_id_bytes.hex(), reason="unknown_room")
            return self._reject(peer, room_id_bytes, "unknown room")
        _log.debug("join_room_known", room_id=room_id_bytes.hex())

        try:
            presentation = unpack_presentation(bytes(payload.presentation))
        except PayloadInvalid as exc:
            _log.info("on_join_request_rejected", room_id=room_id_bytes.hex(), reason="bad_presentation", error=str(exc))
            return self._reject(peer, room_id_bytes, f"presentation decode: {exc}")
        _log.debug(
            "join_presentation_unpacked",
            room_id=room_id_bytes.hex(),
            format_id=presentation.credential.format_id,
            audience=str(presentation.audience),
            nonce_prefix=presentation.nonce.to_bytes()[:6].hex(),
            with_stake=presentation.stake_proof is not None,
        )

        if presentation.audience != self._identity.agent_id:
            _log.info(
                "on_join_request_rejected",
                room_id=room_id_bytes.hex(),
                reason="audience_mismatch",
                expected=str(self._identity.agent_id),
                got=str(presentation.audience),
            )
            return self._reject(peer, room_id_bytes, "audience mismatch")
        _log.debug("join_audience_check_passed", room_id=room_id_bytes.hex())

        signing_payload = presentation.audience.to_bytes() + presentation.nonce.to_bytes()
        if not _ed25519_verify(
            presentation.credential.subject_pubkey,
            signing_payload,
            presentation.holder_signature,
        ):
            _log.info("on_join_request_rejected", room_id=room_id_bytes.hex(), reason="holder_sig_invalid")
            return self._reject(peer, room_id_bytes, "holder signature invalid")
        _log.debug("join_holder_sig_verified", room_id=room_id_bytes.hex())

        now_ms = int(time.time() * 1000)
        if not self._join_nonces.add(presentation.nonce.to_bytes(), ts_ms=now_ms):
            _log.info("on_join_request_rejected", room_id=room_id_bytes.hex(), reason="replay")
            return self._reject(peer, room_id_bytes, "replayed presentation")
        _log.debug("join_nonce_fresh", room_id=room_id_bytes.hex())

        # Lazy-import to avoid a top-level cycle with policy module.
        from communication.trustroom.policy import AdmissionContext as _AdmissionContext

        requester = AgentId.from_pubkey(peer.public_key.veri.vk)
        ctx = _AdmissionContext(
            room_id=room_id,
            requester=requester,
            nonce=presentation.nonce,
            received_at=datetime.now(timezone.utc),
            stake_proof=presentation.stake_proof,
        )

        decision = self._admission.evaluate(presentation, ctx)
        if decision.admitted:
            self._trustroom_state.admit(
                room_id,
                requester,
                presentation.credential.subject_pubkey,
            )
            _log.info(
                "on_join_request_admitted",
                room_id=room_id_bytes.hex(),
                requester=str(requester),
                reason=decision.reason,
                pinned_app_pubkey_prefix=presentation.credential.subject_pubkey[:6].hex(),
            )
        else:
            _log.info(
                "on_join_request_denied",
                room_id=room_id_bytes.hex(),
                requester=str(requester),
                reason=decision.reason,
            )

        self.ez_send(
            peer,
            JoinResponsePayload(
                room_id=room_id_bytes,
                accepted=decision.admitted,
                host_app_pubkey=self._identity.app.pubkey if decision.admitted else b"",
            ),
        )
        _log.debug(
            "join_response_sent",
            room_id=room_id_bytes.hex(),
            accepted=decision.admitted,
        )

    def _reject(self, peer: Any, room_id_bytes: bytes, reason: str) -> None:
        """Send a negative JoinResponse for a malformed/invalid request."""
        try:
            self.ez_send(
                peer,
                JoinResponsePayload(
                    room_id=room_id_bytes, accepted=False, host_app_pubkey=b""
                ),
            )
        except Exception as exc:
            _log.warning("reject_send_failed", reason=reason, error=str(exc))

    @lazy_wrapper(JoinResponsePayload)
    def on_join_response(self, peer: Any, payload: JoinResponsePayload) -> None:
        room_id_bytes = bytes(payload.room_id)
        accepted = bool(payload.accepted)
        host_app_pubkey = bytes(payload.host_app_pubkey)
        _log.info(
            "on_join_response",
            room_id=room_id_bytes.hex(),
            accepted=accepted,
            host_app_pubkey_bytes=len(host_app_pubkey),
        )
        future = self._pending_joins.get(room_id_bytes)
        if future is not None and not future.done():
            future.set_result((accepted, host_app_pubkey))

    @lazy_wrapper(ApplicationMessagePayload)
    def on_application_message(self, peer: Any, payload: ApplicationMessagePayload) -> None:
        _log.info(
            "application_received",
            frame_bytes=len(payload.frame),
            from_mid=peer.mid.hex() if hasattr(peer, "mid") else None,
        )
        if self._trustroom_state is None or self._payload_router is None:
            _log.warning("on_application_message_dropped", reason="not_wired")
            return
        try:
            frame = WireFrame.from_bytes(bytes(payload.frame))
        except (ValueError, PayloadInvalid) as exc:
            _log.info("on_application_message_dropped", reason="malformed_frame", error=str(exc))
            return
        _log.debug(
            "frame_parsed",
            room_id=frame.room_id.to_bytes().hex(),
            sender=str(frame.sender),
            msg_type=frame.msg_type,
            payload_bytes=len(frame.payload),
            nonce_prefix=frame.nonce.to_bytes()[:6].hex(),
            timestamp_ms=frame.timestamp_ms,
        )

        now_ms = int(time.time() * 1000)
        if not is_within_skew(frame.timestamp_ms, now_ms=now_ms):
            _log.info(
                "on_application_message_dropped",
                reason="skew",
                room_id=frame.room_id.to_bytes().hex(),
                frame_ts_ms=frame.timestamp_ms,
                now_ms=now_ms,
                delta_ms=now_ms - frame.timestamp_ms,
            )
            return
        _log.debug("frame_skew_ok", delta_ms=now_ms - frame.timestamp_ms)

        if not self._trustroom_state.is_member(frame.room_id, frame.sender):
            _log.info(
                "on_application_message_dropped",
                reason="not_member",
                room_id=frame.room_id.to_bytes().hex(),
                sender=str(frame.sender),
            )
            return
        _log.debug("frame_membership_ok", room_id=frame.room_id.to_bytes().hex(), sender=str(frame.sender))

        pinned = self._trustroom_state.app_pubkey(frame.room_id, frame.sender)
        if not frame.verify(pinned):
            _log.info(
                "on_application_message_dropped",
                reason="bad_signature",
                room_id=frame.room_id.to_bytes().hex(),
                sender=str(frame.sender),
            )
            return
        _log.debug("frame_signature_verified", sender=str(frame.sender))

        cache_key = (frame.room_id.to_bytes(), frame.sender.to_bytes())
        cache = self._app_nonces.setdefault(cache_key, NonceCache())
        if not cache.add(frame.nonce.to_bytes(), ts_ms=frame.timestamp_ms):
            _log.info(
                "on_application_message_dropped",
                reason="replay",
                room_id=frame.room_id.to_bytes().hex(),
                sender=str(frame.sender),
                nonce_prefix=frame.nonce.to_bytes()[:6].hex(),
            )
            return
        _log.debug("frame_nonce_fresh", nonce_prefix=frame.nonce.to_bytes()[:6].hex())

        try:
            msg = unpack_application_message(frame.payload)
        except (ValueError, PayloadInvalid) as exc:
            _log.info("on_application_message_dropped", reason="payload_decode", error=str(exc))
            return

        _log.info(
            "on_application_message_delivered",
            room_id=frame.room_id.to_bytes().hex(),
            sender=str(frame.sender),
            text_len=len(msg.text),
        )
        self._payload_router.deliver(frame.room_id, frame.sender, msg)

    @lazy_wrapper(RoomAdvertisementPayload)
    def on_room_advertisement(self, peer: Any, payload: RoomAdvertisementPayload) -> None:
        _log.info("on_room_advertisement", ad_len=len(payload.advertisement))

    @lazy_wrapper(StakeOpPayload)
    def on_stake_op(self, peer: Any, payload: StakeOpPayload) -> None:
        _log.info(
            "stake_op_received",
            op_bytes=len(payload.op),
            from_mid=peer.mid.hex() if hasattr(peer, "mid") else None,
        )
        if self._oracle is None:
            _log.warning("on_stake_op_dropped", reason="not_wired")
            return
        try:
            op = StakeOp.from_bytes(bytes(payload.op))
        except PayloadInvalid as exc:
            _log.info("on_stake_op_dropped", reason="malformed", error=str(exc))
            return
        _log.debug(
            "stake_op_parsed",
            kind=str(op.kind),
            actor=str(op.actor),
            target=str(op.target) if op.target is not None else None,
            amount=op.amount,
            purpose=op.purpose,
            nonce_prefix=op.nonce.to_bytes()[:6].hex(),
        )
        # M2 simplification: signature verification on the receive side is skipped.
        # The StakeOp is signed by the actor's wallet key, but receivers don't have
        # a PKI binding (actor → wallet_pubkey) — that registry lands with the
        # colleague's append-only log in M3, which carries authenticated KeyBundle
        # broadcasts. For M2 the sender's local apply is the source of truth and
        # receivers re-apply on trust. NonceCache + per-purpose lock semantics still
        # prevent replay and double-spend at the state-machine level.
        try:
            self._oracle.apply(op)
            _log.info(
                "on_stake_op_applied",
                kind=str(op.kind),
                actor=str(op.actor),
                amount=op.amount,
            )
        except Exception as exc:
            _log.info("on_stake_op_dropped", reason="apply_error", error=str(exc))
