"""Canned, compiler-faithful echo sources for offline SQ3 harness tests.

These stand in for what a real model emits, with no LLM call: a correct echo
overlay, a behaviourally broken one (wrong reply suffix — still passes its own
test vectors), one that loads but fails its vectors (wrong request wire format),
and a non-loading one (sandbox violation). Sandbox-clean: only the permitted
ipv8 imports and a literal community_id.
"""

from __future__ import annotations

from experiments.fixtures import get_spec

ECHO_MD = get_spec("echo").md_text
ECHO_CID = bytes.fromhex(get_spec("echo").community_id_hex)

_ECHO_SOURCE = '''
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver


@vp_compile
class EchoRequestPayload(VariablePayload):
    msg_id = 1
    format_list = ["{req_fmt}"]
    names = ["payload"]


@vp_compile
class EchoResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["varlenH"]
    names = ["payload"]


class GeneratedCommunity(Community, PeerObserver):
    community_id = bytes.fromhex("{cid}")

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.received_responses = []
        self.add_message_handler(EchoRequestPayload, self.on_echo_request)
        self.add_message_handler(EchoResponsePayload, self.on_echo_response)

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, peer) -> None:
        pass

    def on_peer_removed(self, peer) -> None:
        pass

    @lazy_wrapper(EchoRequestPayload)
    def on_echo_request(self, peer, payload) -> None:
        echoed = payload.payload.decode("utf-8") + "{bang}"
        self.ez_send(peer, EchoResponsePayload(echoed.encode("utf-8")))

    @lazy_wrapper(EchoResponsePayload)
    def on_echo_response(self, peer, payload) -> None:
        self.received_responses.append(payload.payload.decode("utf-8"))
'''


def echo_source(*, bang: str = "!", req_fmt: str = "varlenH") -> str:
    return _ECHO_SOURCE.format(cid=ECHO_CID.hex(), bang=bang, req_fmt=req_fmt)


GOOD = echo_source()
BROKEN_BEHAVIOUR = echo_source(bang="?")          # loads + vectors pass, wrong reply
VECTOR_BREAKING = echo_source(req_fmt="20s")      # loads, but vectors won't round-trip
NON_LOADING = "import os\n" + GOOD                 # sandbox violation
