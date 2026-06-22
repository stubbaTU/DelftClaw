"""Reference implementation of ``protocol/examples/echo_overlay.md``.

The trivial rung: no memory beyond a list of received replies; the only
behaviour is the request handler's reply. Ground truth for the echo
conformance scenarios.
"""

from __future__ import annotations

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver

from protocol.compiler import community_id_from_md
from experiments.fixtures import get_spec

# I2 — the reference MUST share the descriptor's content-derived community_id so
# it lands in the same IPv8 community as a compiled echo overlay.
COMMUNITY_ID = community_id_from_md(get_spec("echo").md_text)


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


class EchoReferenceCommunity(Community, PeerObserver):
    """Reference echo community (lifecycle: peer-observer)."""

    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        # Runtime State table: received_responses (list[str]).
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
        # "send ECHO_RESPONSE whose payload is the received payload (utf-8
        # decoded) with an exclamation mark appended, re-encoded as utf-8 bytes."
        echoed = payload.payload.decode("utf-8") + "!"
        self.ez_send(peer, EchoResponsePayload(echoed.encode("utf-8")))

    @lazy_wrapper(EchoResponsePayload)
    def on_echo_response(self, peer: Peer, payload: EchoResponsePayload) -> None:
        # "append the decoded utf-8 string to self.received_responses."
        self.received_responses.append(payload.payload.decode("utf-8"))
