"""Hand-authored reference source for the content_community descriptor.

Used by ``StubLLMClient`` so the compile pipeline can be exercised in
tests without a live LLM endpoint. Mirrors what a well-behaved LLM
should produce given the descriptor at
``protocol/examples/content_community.md``.

The community_id literal in this source must match
``community_id_from_md(content_community.md)`` — keep them in sync.
"""

from __future__ import annotations


CONTENT_COMMUNITY_SOURCE = '''\
import msgpack

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver


@vp_compile
class SearchRequestPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenH"]
    names = ["query"]


@vp_compile
class SearchResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["varlenH"]
    names = ["results"]


class GeneratedCommunity(Community, PeerObserver):
    community_id = bytes.fromhex("0b5cafdd65c3e0021949bdc8f071d830ef5ce66f")

    MAX_RESULTS = 50

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        # Public mutable state (the agent / tests populate / read these directly).
        self.local_index = []        # list of dicts: {magnet, name, size, mime, tags?}
        self.response_cache = []     # list of dicts received from peers
        self.add_message_handler(SearchRequestPayload, self.on_search_request)
        self.add_message_handler(SearchResponsePayload, self.on_search_response)

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, peer: Peer) -> None:
        pass

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    @lazy_wrapper(SearchRequestPayload)
    def on_search_request(self, peer: Peer, payload: SearchRequestPayload) -> None:
        query = payload.query.decode("utf-8").lower()
        results = []
        for entry in self.local_index:
            haystack = entry.get("name", "")
            tags = entry.get("tags", [])
            if isinstance(tags, list):
                haystack = haystack + " " + " ".join(str(t) for t in tags)
            if query == "" or query in haystack.lower():
                results.append(entry)
            if len(results) >= self.MAX_RESULTS:
                break
        body = msgpack.packb(results, use_bin_type=True)
        self.ez_send(peer, SearchResponsePayload(body))

    @lazy_wrapper(SearchResponsePayload)
    def on_search_response(self, peer: Peer, payload: SearchResponsePayload) -> None:
        decoded = msgpack.unpackb(payload.results, raw=False)
        if isinstance(decoded, list):
            self.response_cache.extend(decoded)
'''


if __name__ == "__main__":
    from protocol.compiler import community_id_from_md
    md_path = __file__.replace("_stub.py", ".md")
    print(f"content_community community_id = {community_id_from_md(open(md_path).read()).hex()}")
