"""Reference implementation of ``protocol/examples/file_transfer_overlay.md``.

The top rung. Almost all of its behaviour lives in prose: chunking on the seeder
side, and on the fetcher side out-of-order / duplicate-tolerant buffering,
in-order reassembly, and whole-content sha256 verification deciding the ``ok``
verdict. Ground truth for the file_transfer conformance scenarios (including the
adversarial reordering battery in Step 2).
"""

from __future__ import annotations

import hashlib

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver

from protocol.compiler import community_id_from_md
from experiments.fixtures import get_spec

COMMUNITY_ID = community_id_from_md(get_spec("file_transfer").md_text)  # I2


@vp_compile
class FetchRequestPayload(VariablePayload):
    msg_id = 1
    format_list = ["20s"]
    names = ["content_id"]


@vp_compile
class FetchManifestPayload(VariablePayload):
    msg_id = 2
    format_list = ["20s", "H", "32s"]
    names = ["content_id", "total_chunks", "content_hash"]


@vp_compile
class ChunkPayload(VariablePayload):
    msg_id = 3
    format_list = ["20s", "H", "varlenH"]
    names = ["content_id", "seq", "data"]


@vp_compile
class FetchCompletePayload(VariablePayload):
    msg_id = 4
    format_list = ["20s", "?"]
    names = ["content_id", "ok"]


class FileTransferReferenceCommunity(Community, PeerObserver):
    """Reference chunked-transfer community (lifecycle: peer-observer)."""

    community_id = COMMUNITY_ID
    CHUNK_SIZE = 256

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        # Runtime State: served (seeder side, seeded out of band), transfers
        # (fetcher in-progress reassembly), completed (seeder side verdicts).
        self.served: dict[bytes, bytes] = {}
        self.transfers: dict[str, dict] = {}
        self.completed: dict[str, bool] = {}
        self.add_message_handler(FetchRequestPayload, self.on_fetch_request)
        self.add_message_handler(FetchManifestPayload, self.on_fetch_manifest)
        self.add_message_handler(ChunkPayload, self.on_chunk)
        self.add_message_handler(FetchCompletePayload, self.on_fetch_complete)

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, peer: Peer) -> None:
        pass

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    @lazy_wrapper(FetchRequestPayload)
    def on_fetch_request(self, peer: Peer, payload: FetchRequestPayload) -> None:
        # "look up content_id in self.served. If absent, drop silently. If
        # present, split the content into CHUNK_SIZE-byte chunks, reply with a
        # FETCH_MANIFEST carrying the chunk count and sha256 of the whole
        # content, then send one CHUNK per chunk in ascending seq order."
        content = self.served.get(payload.content_id)
        if content is None:
            return
        chunks = [content[i:i + self.CHUNK_SIZE] for i in range(0, len(content), self.CHUNK_SIZE)]
        content_hash = hashlib.sha256(content).digest()
        self.ez_send(peer, FetchManifestPayload(payload.content_id, len(chunks), content_hash))
        for seq, chunk in enumerate(chunks):
            self.ez_send(peer, ChunkPayload(payload.content_id, seq, chunk))

    @lazy_wrapper(FetchManifestPayload)
    def on_fetch_manifest(self, peer: Peer, payload: FetchManifestPayload) -> None:
        # "create a transfer entry keyed by content_id.hex() recording
        # total_chunks, content_hash, an empty chunk buffer, and a
        # not-yet-complete flag. A repeated manifest resets the entry."
        self.transfers[payload.content_id.hex()] = {
            "total": payload.total_chunks,
            "content_hash": payload.content_hash,
            "chunks": {},
            "complete": False,
            "ok": False,
        }

    @lazy_wrapper(ChunkPayload)
    def on_chunk(self, peer: Peer, payload: ChunkPayload) -> None:
        # "find the transfer keyed by content_id.hex(). If none, or already
        # complete, drop. If seq >= total_chunks, drop. Otherwise store data at
        # seq (a duplicate seq overwrites). When the buffer holds every chunk,
        # reassemble in seq order, compute sha256, mark complete with ok =
        # (digest == content_hash), and send one FETCH_COMPLETE carrying ok."
        transfer = self.transfers.get(payload.content_id.hex())
        if transfer is None or transfer["complete"]:
            return
        if payload.seq >= transfer["total"]:
            return
        transfer["chunks"][payload.seq] = payload.data
        if len(transfer["chunks"]) == transfer["total"]:
            data = b"".join(transfer["chunks"][seq] for seq in range(transfer["total"]))
            transfer["ok"] = hashlib.sha256(data).digest() == transfer["content_hash"]
            transfer["complete"] = True
            self.ez_send(peer, FetchCompletePayload(payload.content_id, transfer["ok"]))

    @lazy_wrapper(FetchCompletePayload)
    def on_fetch_complete(self, peer: Peer, payload: FetchCompletePayload) -> None:
        # "record ok in self.completed keyed by content_id.hex()."
        self.completed[payload.content_id.hex()] = payload.ok
