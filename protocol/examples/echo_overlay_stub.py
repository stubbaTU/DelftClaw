"""Hand-authored reference source for the echo_overlay descriptor.

Used by ``StubLLMClient`` so the compiler pipeline is testable without a
live LLM endpoint. Mirrors what a well-behaved LLM should produce when
asked to compile ``protocol/examples/echo_overlay.md``.

The string is exposed as ``ECHO_OVERLAY_SOURCE`` for direct embedding,
and the file's ``__main__`` shows the community_id the source must declare.
"""

from __future__ import annotations


# Note: Not intended to be imported as a runtime overlay — the AST-sandbox
# rejects this file (it imports things outside ipv8.* on purpose for
# documentation). It exists so we can copy/inspect the literal source.
ECHO_OVERLAY_SOURCE = '''\
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


class GeneratedCommunity(Community, PeerObserver):
    community_id = bytes.fromhex("cb34767cf5594a303df692d0eca46d8cd022a31a")

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.add_message_handler(EchoRequestPayload, self.on_echo_request)
        self.add_message_handler(EchoResponsePayload, self.on_echo_response)
        self.received_responses = []

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
'''


if __name__ == "__main__":
    from protocol.compiler import community_id_from_md
    md_path = __file__.replace("_stub.py", ".md")
    print(f"echo_overlay community_id = {community_id_from_md(open(md_path).read()).hex()}")
