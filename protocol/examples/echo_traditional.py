"""Reference hand-written Community for the traditional-overlay flow.

Demonstrates how a colleague would write a static IPv8 protocol that
skips the markdown + LLM-compile pipeline. The class declares its own
20-byte ``community_id``; payload classes live alongside it in this
module so ``OverlayRegistry._introspect_payload_classes`` can discover
them.

Register via either:

    agent.registry.register_community(EchoTraditionalCommunity)

or at agent boot:

    python -m agent ... --register-community \\
        protocol.examples.echo_traditional:EchoTraditionalCommunity

Local-only — the class is not advertised over the bootstrap community
because Python bytecode has no canonical transmittable form. To make a
similar overlay discoverable across the network, wrap it in a markdown
descriptor and use the v5.1 flow instead.
"""

from __future__ import annotations

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver


@vp_compile
class EchoRequestPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenH"]
    names = ["payload"]


@vp_compile
class EchoResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["varlenH"]
    names = ["payload"]


class EchoTraditionalCommunity(Community, PeerObserver):
    """Tiny echo community used to exercise the traditional-overlay path."""

    community_id = bytes.fromhex("e74071be4ec79a991a9b9d83fb4d6d4c5e7f8a90")

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.received_responses: list[str] = []
        self.add_message_handler(EchoRequestPayload, self.on_echo_request)
        self.add_message_handler(EchoResponsePayload, self.on_echo_response)

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, peer: Peer) -> None:
        pass

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    @lazy_wrapper(EchoRequestPayload)
    def on_echo_request(self, peer: Peer, payload: EchoRequestPayload) -> None:
        echoed = payload.payload.decode("utf-8") + "!"
        self.ez_send(peer, EchoResponsePayload(echoed.encode("utf-8")))

    @lazy_wrapper(EchoResponsePayload)
    def on_echo_response(self, peer: Peer, payload: EchoResponsePayload) -> None:
        self.received_responses.append(payload.payload.decode("utf-8"))
