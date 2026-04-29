"""AgentChannel: the OpenClaw-facing facade over TrustroomCommunity."""

from __future__ import annotations

from typing import TYPE_CHECKING

from communication.payload.broadcaster import Broadcaster
from communication.transport.ipv8_runtime import IPv8Runtime
from communication.trustroom.advertisement import RoomAdvertisement
from communication.trustroom.community import TrustroomCommunity
from communication.trustroom.policy import AdmissionPolicy
from identity.agent_identity import AgentIdentity
from shared.envelopes import BTCPayload
from shared.ids import AgentId, CredentialId, MessageId, RoomId, Txid
from trust.store import TrustStore

if TYPE_CHECKING:
    from communication.channel.inbox import Inbox, IncomingMessage


class AgentChannel:
    """Single class OpenClaw integrates with.

    Wraps `TrustroomCommunity` and exposes ~10 methods the LLM tool layer can call.
    Method bodies will compose calls into community, trust_store, broadcaster, inbox.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        runtime: IPv8Runtime,
        community: TrustroomCommunity,
        trust_store: TrustStore,
        broadcaster: Broadcaster,
        inbox: "Inbox",
    ) -> None:
        # Store all dependencies; do not start the runtime here.
        ...

    async def start(self) -> None:
        # Delegate to runtime.start(); register the community; spin up advertisement loop.
        ...

    async def stop(self) -> None:
        # Tear down in reverse order; close the inbox last.
        ...

    # --- room operations --------------------------------------------------

    def create_room(self, policy: AdmissionPolicy) -> RoomId:
        # Delegate to community.create_room and update the local RoomRegistry.
        ...

    async def join_room(self, room_id: RoomId, vc_id: CredentialId) -> None:
        # Build a Presentation via CredentialPresenter, call community.join_room, await response.
        ...

    def leave_room(self, room_id: RoomId) -> None:
        # Delegate to community.leave_room and remove from RoomRegistry.
        ...

    def list_rooms(self) -> list[RoomId]:
        # Return RoomIds currently in JOINED state.
        ...

    def members(self, room_id: RoomId) -> list[AgentId]:
        # Delegate to community.members.
        ...

    def advertisements(self) -> list[RoomAdvertisement]:
        # Snapshot of currently-known room advertisements.
        ...

    # --- messaging --------------------------------------------------------

    async def send(
        self,
        room_id: RoomId,
        text: str,
        payment: BTCPayload | None = None,
    ) -> MessageId:
        # Build ApplicationMessage via MessageBuilder, hand to community.send.
        ...

    async def recv(self, timeout: float | None = None) -> "IncomingMessage":
        # Pull from the Inbox; blocks up to timeout.
        ...

    # --- payments ---------------------------------------------------------

    def compose_payment(self, recipient: AgentId, amount_sats: int) -> BTCPayload:
        # Resolve recipient's BTC pubkey from their KeyBundle, call PaymentBuilder.compose.
        ...

    def broadcast_payment(self, payload: BTCPayload) -> Txid:
        # Delegate to the Broadcaster.
        ...
