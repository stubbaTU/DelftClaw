"""TrustroomCommunity: the IPv8 Community subclass at the centre of the sub-project."""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Any

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile

from shared.envelopes import ApplicationMessage
from shared.ids import AgentId, MessageId, RoomId
from shared.logging import get_logger

_log = get_logger("trustroom_community")

if TYPE_CHECKING:
    from identity.agent_identity import AgentIdentity
    from communication.admission.join_protocol import AdmissionGate
    from communication.payload.application_message import PayloadRouter
    from communication.trustroom.policy import AdmissionPolicy


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
    format_list = ["varlenH", "?"]
    names = ["room_id", "accepted"]


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


class TrustroomCommunity(Community):
    """Layer 2 IPv8 Community subclass — the network face of every Trustroom."""

    community_id = b"openclawtrustroomv1\x00"  # 20 bytes per IPv8 contract

    class MsgId(IntEnum):
        JOIN_REQUEST = 1
        JOIN_RESPONSE = 2
        APPLICATION = 3
        ROOM_ADVERTISEMENT = 4

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self._identity: "AgentIdentity | None" = None
        self._admission: "AdmissionGate | None" = None
        self._payload_router: "PayloadRouter | None" = None
        self._inbox: list[tuple[Any, ApplicationMessagePayload]] = []  # test seam

        self.add_message_handler(JoinRequestPayload, self.on_join_request)
        self.add_message_handler(JoinResponsePayload, self.on_join_response)
        self.add_message_handler(ApplicationMessagePayload, self.on_application_message)
        self.add_message_handler(RoomAdvertisementPayload, self.on_room_advertisement)

    def wire(
        self,
        *,
        identity: "AgentIdentity",
        admission: "AdmissionGate",
        payload_router: "PayloadRouter",
    ) -> None:
        """Inject dependencies post-construction.

        The IPv8 service constructs Community subclasses from its config dict, so
        higher-level wiring happens once the overlay is loaded.
        """
        self._identity = identity
        self._admission = admission
        self._payload_router = payload_router

    def started(self) -> None:
        """IPv8 lifecycle hook fired by the on_start config entry."""
        _log.info("community_started", peer_mid=self.my_peer.mid.hex())

    # --- public API consumed by AgentChannel --------------------------------

    def create_room(self, policy: "AdmissionPolicy") -> RoomId:
        return RoomId.fresh()

    async def join_room(self, room_id: RoomId, presentation: Any) -> None:
        ...

    def leave_room(self, room_id: RoomId) -> None:
        ...

    async def send_application(self, peer: Any, frame_bytes: bytes) -> None:
        """Wire a signed WireFrame to ``peer`` via IPv8.

        Uses ``ez_send`` so IPv8 prefixes the community + msg id, signs, and frames.
        """
        self.ez_send(peer, ApplicationMessagePayload(frame=frame_bytes))

    def members(self, room_id: RoomId) -> list[AgentId]:
        return []

    # --- IPv8 message handlers ---------------------------------------------

    @lazy_wrapper(JoinRequestPayload)
    def on_join_request(self, peer: Any, payload: JoinRequestPayload) -> None:
        _log.info("on_join_request", room_id=payload.room_id.hex())

    @lazy_wrapper(JoinResponsePayload)
    def on_join_response(self, peer: Any, payload: JoinResponsePayload) -> None:
        _log.info("on_join_response", room_id=payload.room_id.hex(), accepted=payload.accepted)

    @lazy_wrapper(ApplicationMessagePayload)
    def on_application_message(self, peer: Any, payload: ApplicationMessagePayload) -> None:
        _log.info("on_application_message", frame_len=len(payload.frame))
        self._inbox.append((peer, payload))

    @lazy_wrapper(RoomAdvertisementPayload)
    def on_room_advertisement(self, peer: Any, payload: RoomAdvertisementPayload) -> None:
        _log.info("on_room_advertisement", ad_len=len(payload.advertisement))
