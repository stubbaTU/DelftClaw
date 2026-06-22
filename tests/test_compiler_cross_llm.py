"""Empirical zero-shot-determinism test for the overlay compiler.

The architectural bet from Agora is: two different LLMs reading the
same `.md` produce wire-compatible code, because the schema constrains
encoding choices and the compiler runs test vectors before activating
the result. This test puts that bet under load.

We compile ``content_community.md`` against TWO independent inline
variants that emit stylistically-divergent Python (reordered payload
classes, different docstrings, different local variable names,
different but equivalent handler bodies). Both must:

  1. Produce the same 20-byte ``community_id`` (it's content-derived,
     so this is really a tautology — but we assert it.)
  2. Pass every test vector the compiler runs before activation.
  3. Yield ``payload_classes`` whose ``format_list`` matches exactly,
     by construction.

If either variant fails activation the test fails — that's the
fail-closed property the design hinges on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from protocol import community_id_from_md, compile_overlay
from _live_llm import noop_llm


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTENT_MD = (REPO_ROOT / "protocol" / "examples" / "content_community.md").read_text(
    encoding="utf-8"
)
COMMUNITY_ID_HEX = community_id_from_md(CONTENT_MD).hex()


# ---------------------------------------------------------------------------
# Variant A — one valid, conformant content_community implementation. Together
# with Variant B (a stylistically different but wire-equivalent implementation
# below) these stand in for two independent LLM compilations of the same
# descriptor; the test asserts they produce an identical community_id and wire
# format. Defined inline as a local test fixture, fed straight through the
# compile pipeline via llm_source (no live model, no shared stub module).
# ---------------------------------------------------------------------------

VARIANT_A_SOURCE = """```python
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
    community_id = bytes.fromhex(\"""" + COMMUNITY_ID_HEX + """\")
    MAX_RESULTS = 50

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.local_index = []
        self.response_cache = []
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
            hay = entry.get("name", "")
            tags = entry.get("tags", [])
            if isinstance(tags, list):
                hay = hay + " " + " ".join(str(t) for t in tags)
            if query == "" or query in hay.lower():
                results.append(entry)
            if len(results) >= self.MAX_RESULTS:
                break
        self.ez_send(peer, SearchResponsePayload(msgpack.packb(results, use_bin_type=True)))

    @lazy_wrapper(SearchResponsePayload)
    def on_search_response(self, peer: Peer, payload: SearchResponsePayload) -> None:
        decoded = msgpack.unpackb(payload.results, raw=False)
        if isinstance(decoded, list):
            self.response_cache.extend(decoded)
```"""


# ---------------------------------------------------------------------------
# Variant B — same wire shape, stylistically different. Reorders the
# payload classes, drops docstrings, swaps the handler implementation
# to use a different (but functionally equivalent) algorithm, renames
# local variables. Both variants honour the descriptor's structural
# contract (MAX_RESULTS at class scope; local_index / response_cache
# slots assigned in __init__) — anything that diverges from the
# contract is caught by the compiler's structural check (see
# ``VARIANT_C_MISSING_CONSTANT`` below).
# ---------------------------------------------------------------------------

VARIANT_B_SOURCE = """```python
import msgpack

from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver


@vp_compile
class SearchResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["varlenH"]
    names = ["results"]


@vp_compile
class SearchRequestPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenH"]
    names = ["query"]


class GeneratedCommunity(Community, PeerObserver):
    community_id = bytes.fromhex(\"""" + COMMUNITY_ID_HEX + """\")
    MAX_RESULTS = 50

    def __init__(self, cfg: CommunitySettings) -> None:
        super().__init__(cfg)
        self.local_index = []
        self.response_cache = []
        self.add_message_handler(SearchRequestPayload, self.on_search_request)
        self.add_message_handler(SearchResponsePayload, self.on_search_response)

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, p: Peer) -> None:
        pass

    def on_peer_removed(self, p: Peer) -> None:
        pass

    @lazy_wrapper(SearchRequestPayload)
    def on_search_request(self, sender: Peer, msg: SearchRequestPayload) -> None:
        q = msg.query.decode("utf-8").lower()
        hits = list()
        i = 0
        while i < len(self.local_index) and len(hits) < self.MAX_RESULTS:
            row = self.local_index[i]
            tag_str = " ".join(str(t) for t in row.get("tags", []) if t is not None)
            blob = (row.get("name", "") + " " + tag_str).lower()
            if not q or q in blob:
                hits.append(row)
            i += 1
        self.ez_send(sender, SearchResponsePayload(msgpack.packb(hits, use_bin_type=True)))

    @lazy_wrapper(SearchResponsePayload)
    def on_search_response(self, sender: Peer, msg: SearchResponsePayload) -> None:
        data = msgpack.unpackb(msg.results, raw=False)
        if isinstance(data, list):
            for item in data:
                self.response_cache.append(item)
```
"""


# ---------------------------------------------------------------------------
# Variant C — non-conforming. Omits the MAX_RESULTS constant required
# by the descriptor's # Constants table (inlines 50 instead). Wire
# format is still identical, but the structural check refuses to
# activate the overlay — this is the brittleness fix the schema
# upgrade is meant to enforce.
# ---------------------------------------------------------------------------

VARIANT_C_MISSING_CONSTANT = """```python
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
    community_id = bytes.fromhex(\"""" + COMMUNITY_ID_HEX + """\")

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.local_index = []
        self.response_cache = []
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
            if query in entry.get("name", "").lower():
                results.append(entry)
            if len(results) >= 50:
                break
        self.ez_send(peer, SearchResponsePayload(msgpack.packb(results, use_bin_type=True)))

    @lazy_wrapper(SearchResponsePayload)
    def on_search_response(self, peer: Peer, payload: SearchResponsePayload) -> None:
        decoded = msgpack.unpackb(payload.results, raw=False)
        if isinstance(decoded, list):
            self.response_cache.extend(decoded)
```
"""


# ---------------------------------------------------------------------------
# Variant D — non-conforming. Renames the runtime-state slot
# ``response_cache`` to ``responses``. Wire format still identical;
# structural check rejects.
# ---------------------------------------------------------------------------

VARIANT_D_RENAMED_SLOT = """```python
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
    community_id = bytes.fromhex(\"""" + COMMUNITY_ID_HEX + """\")
    MAX_RESULTS = 50

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.local_index = []
        self.responses = []   # WRONG NAME — schema says response_cache
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
        hits = [e for e in self.local_index if query in e.get("name", "").lower()][: self.MAX_RESULTS]
        self.ez_send(peer, SearchResponsePayload(msgpack.packb(hits, use_bin_type=True)))

    @lazy_wrapper(SearchResponsePayload)
    def on_search_response(self, peer: Peer, payload: SearchResponsePayload) -> None:
        decoded = msgpack.unpackb(payload.results, raw=False)
        if isinstance(decoded, list):
            self.responses.extend(decoded)
```
"""


# ---------------------------------------------------------------------------
# The cross-LLM test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "source",
    [VARIANT_A_SOURCE, VARIANT_B_SOURCE],
    ids=["A_reference", "B_alternate"],
)
def test_each_variant_compiles_and_passes_test_vectors(source):
    """Each variant must independently activate (test vectors + AST)."""
    compiled = compile_overlay(CONTENT_MD, noop_llm(), llm_source=source)
    assert compiled.community_id.hex() == COMMUNITY_ID_HEX
    assert "SEARCH_REQUEST" in compiled.payload_classes
    assert "SEARCH_RESPONSE" in compiled.payload_classes


def test_both_variants_produce_identical_community_id_and_wire_format():
    """Activation success on both variants proves the determinism claim
    for THIS overlay against THIS pair of independent implementations —
    fail-closed via the compiler's mandatory test vectors."""
    compiled_a = compile_overlay(CONTENT_MD, noop_llm(), llm_source=VARIANT_A_SOURCE)
    compiled_b = compile_overlay(CONTENT_MD, noop_llm(), llm_source=VARIANT_B_SOURCE)

    # Content-derived id: same .md -> same id, irrespective of LLM output.
    assert compiled_a.community_id == compiled_b.community_id

    # Per-message wire formats match — this is the load-bearing claim.
    for name in ("SEARCH_REQUEST", "SEARCH_RESPONSE"):
        cls_a = compiled_a.payload_classes[name]
        cls_b = compiled_b.payload_classes[name]
        assert cls_a.msg_id == cls_b.msg_id
        assert cls_a.format_list == cls_b.format_list
        assert cls_a.names == cls_b.names


def test_variant_b_actually_differs_from_variant_a():
    """Sanity check: if the variants accidentally became identical, the
    cross-LLM claim is vacuous. Compare the raw source strings."""
    assert VARIANT_A_SOURCE != VARIANT_B_SOURCE
    # And the difference is real — Variant B reorders the payload classes
    # (SearchResponse declared before SearchRequest).
    b_inner = VARIANT_B_SOURCE
    assert b_inner.index("SearchResponsePayload") < b_inner.index("SearchRequestPayload")


# ---------------------------------------------------------------------------
# Fail-closed tests for the structural contract.
# ---------------------------------------------------------------------------

def test_variant_c_missing_constant_is_rejected():
    """A wire-compatible LLM output that omits a `# Constants` entry
    fails activation. This is the brittleness the schema upgrade is
    designed to catch."""
    from protocol.compiler import ProtocolCompileError
    with pytest.raises(ProtocolCompileError, match="MAX_RESULTS"):
        compile_overlay(CONTENT_MD, noop_llm(), llm_source=VARIANT_C_MISSING_CONSTANT)


def test_variant_d_renamed_runtime_state_slot_is_rejected():
    """A wire-compatible LLM output that renames a `# Runtime State`
    slot (response_cache → responses) fails activation."""
    from protocol.compiler import ProtocolCompileError
    with pytest.raises(ProtocolCompileError, match="response_cache"):
        compile_overlay(CONTENT_MD, noop_llm(), llm_source=VARIANT_D_RENAMED_SLOT)
