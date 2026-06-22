"""Step 5 gate: the authoring arm (Flow B), offline.

Two reference-free measures, since an authored document has no human oracle:

  * the faithfulness rubric must accept a structurally complete authored protocol
    and reject one that omits the rung-defining structure (so a model cannot
    climb the ladder by under-specifying); and
  * adoption interop must accept two equivalent compiles of a document and reject
    an adopter that diverges on a reply — the failure mode the old
    length-equality verdict missed.
"""

from __future__ import annotations

import pytest

from _echo_sources import BROKEN_BEHAVIOUR, ECHO_CID, GOOD
from agent.overlay_authoring import synthesize_overlay_markdown
from protocol.compiler import parse_md
from experiments.adoption import adoption_interop
from experiments.faithfulness import check_faithfulness
from experiments.fixtures import get_spec
from experiments.live_interop import load_overlay


def _doc(messages, runtime_state, samples, *, name="proto"):
    """Synthesize a descriptor from authoring args, then parse it (the Flow-B
    author -> document path, minus the LLM)."""
    md = synthesize_overlay_markdown(
        name=name, version="1.0.0", description="d", change_summary="c",
        messages=messages, runtime_state=runtime_state, samples=samples,
        author_id="dclaw1study")
    return parse_md(md)


# ---------------------------------------------------------------------------
# Faithfulness rubric
# ---------------------------------------------------------------------------

def test_rubric_accepts_a_faithful_file_transfer() -> None:
    parsed = _doc(
        name="xfer",
        messages=[
            {"name": "REQ", "msg_id": 1,
             "fields": [{"name": "cid", "encoding": "hash20", "description": "id"}],
             "handler": "look up cid in served and stream it"},
            {"name": "MANIFEST", "msg_id": 2,
             "fields": [{"name": "cid", "encoding": "hash20", "description": "id"},
                        {"name": "count", "encoding": "uint16-be", "description": "n"},
                        {"name": "digest", "encoding": "hash32", "description": "sha256"}],
             "handler": "create a transfer entry keyed by cid"},
            {"name": "PIECE", "msg_id": 3,
             "fields": [{"name": "cid", "encoding": "hash20", "description": "id"},
                        {"name": "idx", "encoding": "uint16-be", "description": "seq"},
                        {"name": "blob", "encoding": "varlenH", "description": "bytes"}],
             "handler": "buffer the piece; when complete verify the digest"},
        ],
        runtime_state=[
            {"name": "served", "type": "dict", "description": "id->bytes"},
            {"name": "transfers", "type": "dict", "description": "in-progress"},
        ],
        samples={
            "REQ": {"cid": "11" * 20},
            "MANIFEST": {"cid": "11" * 20, "count": 1, "digest": "22" * 32},
            "PIECE": {"cid": "11" * 20, "idx": 0, "blob": "ABC"},
        })
    result = check_faithfulness("file_transfer", parsed)
    assert result.ok, result.missing


def test_rubric_rejects_an_underspecified_file_transfer() -> None:
    """A trivial one-message protocol with no hash, no chunk, no transfer state —
    easy to compile and make agree, but it is not a file-transfer."""
    parsed = _doc(
        name="fake",
        messages=[{"name": "GET", "msg_id": 1,
                   "fields": [{"name": "cid", "encoding": "hash20", "description": "id"}],
                   "handler": "send the file back somehow"}],
        runtime_state=[{"name": "log", "type": "list", "description": "events"}],
        samples={"GET": {"cid": "11" * 20}})
    result = check_faithfulness("file_transfer", parsed)
    assert not result.ok
    # the rung-defining structure is reported missing
    assert any("32-byte" in m for m in result.missing)
    assert any("sequence number" in m for m in result.missing)
    assert any("in-progress transfers" in m for m in result.missing)


def test_rubric_rejects_payment_without_keyed_dict() -> None:
    """Three messages and an amount, but the pending state is a list, not a
    requester-keyed dict — so it cannot de-duplicate per requester."""
    parsed = _doc(
        name="pay",
        messages=[
            {"name": "REQ", "msg_id": 1,
             "fields": [{"name": "amt", "encoding": "uint64-be", "description": "sats"}],
             "handler": "record it"},
            {"name": "OFFER", "msg_id": 2,
             "fields": [{"name": "amt", "encoding": "uint64-be", "description": "sats"}],
             "handler": "record it"},
            {"name": "NOTIFY", "msg_id": 3,
             "fields": [{"name": "amt", "encoding": "uint64-be", "description": "sats"}],
             "handler": "record it"},
        ],
        runtime_state=[{"name": "events", "type": "list", "description": "all events"}],
        samples={"REQ": {"amt": 1}, "OFFER": {"amt": 1}, "NOTIFY": {"amt": 1}})
    result = check_faithfulness("payment", parsed)
    assert not result.ok
    assert any("keyed by requester" in m for m in result.missing)


@pytest.mark.parametrize("rung", ["echo", "content_community", "payment", "file_transfer"])
def test_rubric_accepts_the_canonical_fixed_specs(rung: str) -> None:
    """The four shipped descriptors are by construction faithful — the rubric
    must not reject the very protocols it is modelled on."""
    spec_name = rung
    parsed = get_spec(spec_name).parsed
    result = check_faithfulness(rung, parsed)
    assert result.ok, result.missing


# ---------------------------------------------------------------------------
# Adoption interop (reference-free)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_adoption_interop_accepts_equivalent_compiles() -> None:
    parsed = get_spec("echo").parsed
    author = load_overlay(GOOD, ECHO_CID)
    adopter = load_overlay(GOOD, ECHO_CID)
    result = await adoption_interop(author, adopter, parsed, ECHO_CID)
    assert result.ok


@pytest.mark.asyncio
async def test_adoption_interop_rejects_reply_divergence() -> None:
    """The adopter replies "?" instead of "!" — invisible in its own receive
    state, visible in the author's recorded reply. Both-node observation catches
    it."""
    parsed = get_spec("echo").parsed
    author = load_overlay(GOOD, ECHO_CID)
    adopter = load_overlay(BROKEN_BEHAVIOUR, ECHO_CID)
    result = await adoption_interop(author, adopter, parsed, ECHO_CID)
    assert not result.ok
    assert result.detail and "A.received_responses" in result.detail
