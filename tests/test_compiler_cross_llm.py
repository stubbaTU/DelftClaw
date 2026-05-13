"""Empirical zero-shot-determinism test for the overlay compiler.

The architectural bet from Agora is: two different LLMs reading the
same `.md` produce wire-compatible code, because the schema constrains
encoding choices and the compiler runs test vectors before activating
the result. This test puts that bet under load.

We compile ``content_community.md`` against TWO ``StubLLMClient``
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

from protocol import StubLLMClient, community_id_from_md, compile_overlay


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTENT_MD = (REPO_ROOT / "protocol" / "examples" / "content_community.md").read_text(
    encoding="utf-8"
)
COMMUNITY_ID_HEX = community_id_from_md(CONTENT_MD).hex()


# ---------------------------------------------------------------------------
# Variant A — the reference stub the repo already uses elsewhere.
# ---------------------------------------------------------------------------

from protocol.examples.content_community_stub import CONTENT_COMMUNITY_SOURCE
VARIANT_A_SOURCE = "```python\n" + CONTENT_COMMUNITY_SOURCE + "```"


# ---------------------------------------------------------------------------
# Variant B — same wire shape, stylistically different. Reorders the
# payload classes, drops docstrings, swaps the handler implementation
# to use a different (but functionally equivalent) algorithm, renames
# local variables, swaps the MAX_RESULTS constant for an inline int.
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
        cap = 50
        hits = list()
        i = 0
        while i < len(self.local_index) and len(hits) < cap:
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
# The cross-LLM test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "source",
    [VARIANT_A_SOURCE, VARIANT_B_SOURCE],
    ids=["A_reference", "B_alternate"],
)
def test_each_variant_compiles_and_passes_test_vectors(source):
    """Each LLM variant must independently activate (test vectors + AST)."""
    llm = StubLLMClient(sources={COMMUNITY_ID_HEX: source})
    compiled = compile_overlay(CONTENT_MD, llm)
    assert compiled.community_id.hex() == COMMUNITY_ID_HEX
    assert "SEARCH_REQUEST" in compiled.payload_classes
    assert "SEARCH_RESPONSE" in compiled.payload_classes


def test_both_variants_produce_identical_community_id_and_wire_format():
    """Activation success on both variants proves the determinism claim
    for THIS overlay against THIS pair of LLM outputs — fail-closed via
    the compiler's mandatory test vectors."""
    llm_a = StubLLMClient(sources={COMMUNITY_ID_HEX: VARIANT_A_SOURCE})
    llm_b = StubLLMClient(sources={COMMUNITY_ID_HEX: VARIANT_B_SOURCE})

    compiled_a = compile_overlay(CONTENT_MD, llm_a)
    compiled_b = compile_overlay(CONTENT_MD, llm_b)

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
