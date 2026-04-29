"""Room advertisements gossiped over the IPv8 community."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable

from shared.ids import AgentId, RoomId

if TYPE_CHECKING:
    from communication.trustroom.community import TrustroomCommunity


@dataclass(frozen=True)
class RoomAdvertisement:
    """Gossiped on the discovery topic; tells other agents what rooms exist and how to join."""

    room_id: RoomId
    host: AgentId
    policy_descriptor: str
    # `policy_descriptor` is a human-readable summary of the AdmissionPolicy.
    accepted_formats: list[str]
    # `accepted_formats` lists VC format ids the host will verify (e.g. ["w3c-jwt", "sd-jwt"]).


class Advertiser:
    """Publishes and tracks RoomAdvertisements over the IPv8 community."""

    def __init__(self, community: "TrustroomCommunity") -> None:
        # Hold a reference to the community so we can broadcast on it.
        ...

    def publish(self, ad: RoomAdvertisement) -> None:
        # Broadcast the advertisement as MsgId.ROOM_ADVERTISEMENT to every known peer.
        ...

    def discovered(self) -> Iterable[RoomAdvertisement]:
        # Snapshot of every currently-known advertisement (received from others or self).
        ...
