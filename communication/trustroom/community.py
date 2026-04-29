"""TrustroomCommunity: the IPv8 Community subclass at the centre of the sub-project."""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Any

from identity.agent_identity import AgentIdentity
from shared.credentials import Presentation
from shared.envelopes import ApplicationMessage
from shared.ids import AgentId, MessageId, RoomId

if TYPE_CHECKING:
    from communication.admission.join_protocol import AdmissionGate
    from communication.messaging.secure_group_session import SecureGroupSessionFactory
    from communication.payload.application_message import PayloadRouter
    from communication.trustroom.policy import AdmissionPolicy
    from communication.wire.codec import Codec


class TrustroomCommunity:
    """Layer 2 IPv8 Community subclass.

    In the real implementation this inherits from ``ipv8.community.Community``;
    the skeleton keeps it as a plain class so the file stays importable without
    py-ipv8 installed.
    """

    community_id = b"openclawtrustrm0"

    class MsgId(IntEnum):
        """Wire-level message-type discriminants used by IPv8 message dispatch."""

        JOIN_REQUEST = 1
        JOIN_RESPONSE = 2
        APPLICATION = 3
        GROUP_COMMIT = 4
        ROOM_ADVERTISEMENT = 5

    def __init__(
        self,
        my_peer: Any,
        endpoint: Any,
        network: Any,
        *,
        identity: AgentIdentity,
        admission: "AdmissionGate",
        secure_session_factory: "SecureGroupSessionFactory",
        payload_router: "PayloadRouter",
        codec: "Codec",
    ) -> None:
        # Wire all dependencies; do not start gossip yet — that happens in started().
        ...

    def started(self) -> None:
        # IPv8 lifecycle hook: install message handlers, start the room-advertisement loop.
        ...

    # --- public API consumed by AgentChannel --------------------------------

    def create_room(self, policy: "AdmissionPolicy") -> RoomId:
        # Mint a fresh RoomId, build a SecureGroupSession with self as sole member, gossip the ad.
        ...

    async def join_room(self, room_id: RoomId, presentation: Presentation) -> None:
        # Send JOIN_REQUEST to the room host, await JOIN_RESPONSE, install received welcome blob.
        ...

    def leave_room(self, room_id: RoomId) -> None:
        # Rotate group keys to remove self, broadcast the resulting GROUP_COMMIT, drop local state.
        ...

    async def send(self, room_id: RoomId, message: ApplicationMessage) -> MessageId:
        # Encrypt via SecureGroupSession, frame via wire.codec, hand to the IPv8 endpoint.
        ...

    def members(self, room_id: RoomId) -> list[AgentId]:
        # Return the current admitted members from the local SecureGroupSession.
        ...

    # --- IPv8 message handlers ---------------------------------------------

    def on_join_request(self, peer: Any, payload: bytes) -> None:
        # Decode payload, ask AdmissionGate to verify+evaluate, send JOIN_RESPONSE accordingly.
        ...

    def on_join_response(self, peer: Any, payload: bytes) -> None:
        # If admitted, install welcome blob into SecureGroupSession; else surface AdmissionDenied.
        ...

    def on_application_message(self, peer: Any, payload: bytes) -> None:
        # Verify wire signature, decrypt, hand the ApplicationMessage to PayloadRouter.
        ...

    def on_group_commit(self, peer: Any, payload: bytes) -> None:
        # Apply a Layer-4 epoch advance — add/remove member, rotate group key.
        ...

    def on_room_advertisement(self, peer: Any, payload: bytes) -> None:
        # Cache a discovered RoomAdvertisement for higher layers to query.
        ...
