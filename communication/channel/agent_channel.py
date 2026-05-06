"""AgentChannel: the OpenClaw-facing facade over TrustroomCommunity."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from communication.admission.codec import pack_presentation
from communication.admission.join_protocol import AdmissionGate
from communication.admission.presenter import CredentialPresenter
from communication.admission.verifier import MultiFormatVerifier
from communication.channel.inbox import Inbox, IncomingMessage
from communication.payload.application_message import (
    MessageBuilder,
    PayloadRouter,
    pack_application_message,
)
from communication.trustroom.community import TrustroomCommunity
from communication.trustroom.lifecycle import RoomRegistry, RoomState
from communication.trustroom.state import TrustroomState
from shared.envelopes import WireFrame
from shared.errors import AdmissionDenied
from shared.ids import AgentId, CredentialId, Epoch, MessageId, Nonce, RoomId
from shared.logging import get_logger
from trust.formats.toy import ToyEd25519Format
from trust.revocation import NullRevocationChecker, RevocationChecker

_log = get_logger("agent_channel")

if TYPE_CHECKING:
    from communication.transport.ipv8_runtime import IPv8Runtime
    from communication.trustroom.advertisement import RoomAdvertisement
    from communication.trustroom.policy import AdmissionPolicy
    from identity.agent_identity import AgentIdentity
    from trust.formats.base import CredentialFormat
    from trust.store import TrustStore


class AgentChannel:
    """Single class OpenClaw integrates with.

    Wraps `TrustroomCommunity` and exposes ~9 methods the LLM tool layer can call.
    Method bodies compose calls into community, trust_store, inbox.
    """

    def __init__(
        self,
        identity: "AgentIdentity",
        runtime: "IPv8Runtime",
        trust_store: "TrustStore",
        *,
        credential_format: "CredentialFormat | None" = None,
        revocation: RevocationChecker | None = None,
        inbox: Inbox | None = None,
    ) -> None:
        self._identity = identity
        self._runtime = runtime
        self._trust_store = trust_store
        self._format = credential_format or ToyEd25519Format()
        self._revocation = revocation or NullRevocationChecker()
        self._inbox = inbox or Inbox()

        self._community: TrustroomCommunity | None = None
        self._trustroom_state = TrustroomState()
        self._registry = RoomRegistry()
        self._policies: dict[bytes, "AdmissionPolicy"] = {}
        self._presenter = CredentialPresenter(
            store=self._trust_store,
            format=self._format,
            identity=self._identity,
        )

        # Tell the runtime to load TrustroomCommunity at startup. Idempotent
        # against double-registration so a caller can hand us a runtime that
        # already has other overlays registered (e.g. ClawPoCCommunity).
        self._runtime.register_community(TrustroomCommunity)

    async def start(self) -> None:
        _log.info("channel_start")
        await self._runtime.start()
        community: TrustroomCommunity = self._runtime.get_overlay(TrustroomCommunity)
        verifier = MultiFormatVerifier(
            formats={self._format.format_id: self._format},
            revocation=self._revocation,
        )
        gate = AdmissionGate(verifier=verifier, policy=_DispatchingPolicy(self._policies))
        community.wire(
            identity=self._identity,
            admission=gate,
            payload_router=PayloadRouter(self._inbox),
            trustroom_state=self._trustroom_state,
        )
        self._community = community

    async def stop(self) -> None:
        _log.info("channel_stop")
        await self._runtime.stop()
        self._community = None

    # --- room operations --------------------------------------------------

    def create_room(self, policy: "AdmissionPolicy") -> RoomId:
        community = self._require_community()
        room_id = community.create_room(policy)
        self._policies[room_id.to_bytes()] = policy
        self._registry.add(room_id, RoomState.JOINED)  # host is auto-joined
        _log.info("room_created", room_id=str(room_id), policy=type(policy).__name__)
        return room_id

    async def join_room(
        self,
        room_id: RoomId,
        vc_id: CredentialId,
        host_peer: Any,
    ) -> None:
        community = self._require_community()
        _log.info("join_attempt", room_id=str(room_id), vc_id=str(vc_id))
        host_agent_id = AgentId.from_pubkey(host_peer.public_key.veri.vk)
        presentation = self._presenter.present(
            vc_id=vc_id,
            audience=host_agent_id,
            nonce=Nonce.fresh(),
        )
        self._registry.add(room_id, RoomState.PENDING_JOIN)
        accepted = await community.send_join_request(
            host_peer=host_peer,
            room_id=room_id,
            presentation_bytes=pack_presentation(presentation),
        )
        if not accepted:
            self._registry.add(room_id, RoomState.ERROR)
            raise AdmissionDenied(f"host refused join for room {room_id}")
        self._registry.add(room_id, RoomState.JOINED)
        # M1 keeps only the host's TrustroomState populated. Joiners do not yet
        # verify host-originated WireFrames; that requires either a host-app-pubkey
        # field on JoinResponsePayload or a separate membership broadcast (M2).
        _log.info("join_succeeded", room_id=str(room_id))

    def leave_room(self, room_id: RoomId) -> None:
        community = self._require_community()
        community.leave_room(room_id)
        self._trustroom_state.remove(room_id)
        self._registry.remove(room_id)
        self._policies.pop(room_id.to_bytes(), None)
        _log.info("room_left", room_id=str(room_id))

    def list_rooms(self) -> list[RoomId]:
        return self._registry.all_joined()

    def members(self, room_id: RoomId) -> list[AgentId]:
        return self._trustroom_state.members(room_id)

    def advertisements(self) -> list["RoomAdvertisement"]:
        # Advertiser is deferred (M2). Discovery is out-of-band in M1.
        return []

    # --- messaging --------------------------------------------------------

    async def send(
        self,
        room_id: RoomId,
        text: str,
        target_peer: Any,
    ) -> MessageId:
        community = self._require_community()
        _log.info("send_attempt", room_id=str(room_id), text_len=len(text))
        msg = MessageBuilder().with_text(text).build()
        blob = pack_application_message(msg)
        import time

        frame = WireFrame.unsigned(
            room_id=room_id,
            epoch=Epoch(0),
            sender=self._identity.agent_id,
            msg_type=int(TrustroomCommunity.MsgId.APPLICATION),
            nonce=Nonce.fresh(),
            timestamp_ms=int(time.time() * 1000),
            payload=blob,
        )
        signed = frame.sign(self._identity.app.key)
        await community.send_application(target_peer, signed.to_bytes())
        return MessageId.fresh()

    async def recv(self, timeout: float | None = None) -> IncomingMessage:
        return await self._inbox.get(timeout)

    # --- internals --------------------------------------------------------

    @property
    def community(self) -> TrustroomCommunity:
        return self._require_community()

    def _require_community(self) -> TrustroomCommunity:
        if self._community is None:
            raise RuntimeError("AgentChannel.start() has not been awaited yet")
        return self._community


class _DispatchingPolicy:
    """Policy adapter: dispatches by ``ctx.room_id`` into a per-room ``AdmissionPolicy``."""

    def __init__(self, by_room: dict[bytes, "AdmissionPolicy"]) -> None:
        self._by_room = by_room

    def evaluate(self, vc, ctx):
        from communication.trustroom.policy import AdmissionDecision

        policy = self._by_room.get(ctx.room_id.to_bytes())
        if policy is None:
            return AdmissionDecision(admitted=False, reason="no policy for room")
        return policy.evaluate(vc, ctx)
