"""Reference implementation of ``protocol/examples/content_community.md``.

The first stateful rung: a search handler whose correctness lives in the prose,
not the encoding tables — case-insensitive substring matching over a seeded
catalogue, declared order, and truncation to ``MAX_RESULTS``. Ground truth for
the content_community conformance scenarios.
"""

from __future__ import annotations

import msgpack
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver

from protocol.compiler import community_id_from_md
from experiments.fixtures import get_spec

COMMUNITY_ID = community_id_from_md(get_spec("content_community").md_text)  # I2


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


class ContentReferenceCommunity(Community, PeerObserver):
    """Reference content-search community (lifecycle: peer-observer)."""

    community_id = COMMUNITY_ID
    MAX_RESULTS = 50

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        # Runtime State: local_index (seeded out of band), response_cache.
        self.local_index: list[dict] = []
        self.response_cache: list[dict] = []
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
        # "scan self.local_index using a case-insensitive substring match against
        # each entry's name and any free-text tags. Return at most MAX_RESULTS
        # entries via SEARCH_RESPONSE in declared order. An empty query returns
        # the full index (truncated to MAX_RESULTS)."
        query = payload.query.decode("utf-8").lower()
        matches: list[dict] = []
        for entry in self.local_index:
            if query == "":
                hit = True
            else:
                name = str(entry.get("name", "")).lower()
                tags = [str(t).lower() for t in entry.get("tags", []) or []]
                hit = query in name or any(query in tag for tag in tags)
            if hit:
                # SEARCH_RESPONSE carries {magnet, name, size, mime} (no tags).
                matches.append({
                    "magnet": entry.get("magnet"),
                    "name": entry.get("name"),
                    "size": entry.get("size"),
                    "mime": entry.get("mime"),
                })
                if len(matches) >= self.MAX_RESULTS:
                    break
        self.ez_send(peer, SearchResponsePayload(msgpack.packb(matches, use_bin_type=True)))

    @lazy_wrapper(SearchResponsePayload)
    def on_search_response(self, peer: Peer, payload: SearchResponsePayload) -> None:
        # "decode the msgpack list and append each entry to self.response_cache."
        for entry in msgpack.unpackb(payload.results, raw=False):
            self.response_cache.append(entry)
