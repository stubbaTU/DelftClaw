"""SQ4 (Table IV): authored-protocol self/cross interop at two levels, offline.

Three things to pin:

  * the generic functional projection drops compile-invented metadata (keys no
    message declares) while preserving identity-keyed containers — the same
    contract the fixed arm hand-writes per slot, derived here from the document;
  * two-level agreement separates a wrong reply (caught at both levels) from a
    metadata-only difference (caught only at the representational level); and
  * the session scorer pools a document's same-model (self) and different-model
    (cross) compiles into the four Table IV cells, honouring a faithful filter.
"""

from __future__ import annotations

import json

import pytest

from _echo_sources import BROKEN_BEHAVIOUR, ECHO_CID, GOOD
from protocol.compiler import parse_md
from experiments.authored_levels import (
    agree_two_levels,
    declared_fields,
    functional_project,
    score_authored_session,
)
from experiments.fixtures import get_spec


# ---------------------------------------------------------------------------
# Functional projection
# ---------------------------------------------------------------------------

def test_functional_project_drops_undeclared_record_keys() -> None:
    """A requester-keyed map of payment records: the role keys survive, and inside
    each record only the declared message fields (amount_sats, memo) are kept — an
    invented timestamp is dropped."""
    fields = frozenset({"amount_sats", "memo"})
    state = {"A": {"amount_sats": 5000, "memo": "rent", "ts": 1700000000},
             "B": {"amount_sats": 30, "memo": "x", "received_at": 9}}
    assert functional_project(state, fields) == {
        "A": {"amount_sats": 5000, "memo": "rent"},
        "B": {"amount_sats": 30, "memo": "x"},
    }


def test_functional_project_drops_undeclared_list_fields() -> None:
    """A result cache (list of records): keep the declared response fields, drop a
    'tags' field the search response never carried."""
    fields = frozenset({"magnet", "name", "size", "mime"})
    cache = [{"magnet": "m1", "name": "calc", "size": 10, "mime": "x", "tags": ["math"]}]
    assert functional_project(cache, fields) == [
        {"magnet": "m1", "name": "calc", "size": 10, "mime": "x"}]


def test_functional_project_leaves_scalars_and_unmatched_records_whole() -> None:
    """A list of scalars passes through; a record with no declared key is compared
    in full (we cannot tell contract from metadata when nothing matches)."""
    fields = frozenset({"amount_sats"})
    assert functional_project(["hi!", "café!"], fields) == ["hi!", "café!"]
    assert functional_project({"complete": True, "ok": False}, fields) == {
        "complete": True, "ok": False}


def test_declared_fields_unions_all_message_fields() -> None:
    parsed = get_spec("payment").parsed
    fields = declared_fields(parsed)
    assert {"amount_sats", "memo", "txid", "reason"} <= fields


# ---------------------------------------------------------------------------
# Two-level agreement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_agree_two_levels_identical_compiles_agree() -> None:
    from experiments.live_interop import load_overlay
    parsed = get_spec("echo").parsed
    a = load_overlay(GOOD, ECHO_CID)
    b = load_overlay(GOOD, ECHO_CID)
    func_ok, repr_ok = await agree_two_levels(a, b, parsed, ECHO_CID)
    assert func_ok and repr_ok


@pytest.mark.asyncio
async def test_agree_two_levels_wrong_reply_fails_both_levels() -> None:
    """The adopter replies '?' instead of '!': the divergence lands in the peer's
    recorded replies (plain strings, not metadata), so it fails functionally too."""
    from experiments.live_interop import load_overlay
    parsed = get_spec("echo").parsed
    good = load_overlay(GOOD, ECHO_CID)
    broken = load_overlay(BROKEN_BEHAVIOUR, ECHO_CID)
    func_ok, repr_ok = await agree_two_levels(good, broken, parsed, ECHO_CID)
    assert not func_ok and not repr_ok


# ---------------------------------------------------------------------------
# Session scorer (end-to-end over a fabricated authored/ layout)
# ---------------------------------------------------------------------------

def _write_doc(session, rung, run_id, *, author, adopter, faithful,
               author_src, author2_src, adopter_src,
               author_outcome="ok", author2_outcome="ok", adopter_outcome="ok") -> None:
    base = session / "authored" / rung
    base.mkdir(parents=True, exist_ok=True)
    (base / f"{run_id}.md").write_text(get_spec(rung).md_text, encoding="utf-8")
    (base / f"{run_id}.author.py").write_text(author_src, encoding="utf-8")
    (base / f"{run_id}.author2.py").write_text(author2_src, encoding="utf-8")
    (base / f"{run_id}.adopter.py").write_text(adopter_src, encoding="utf-8")
    with open(session / "runs.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"arm": "authoring", "run_id": run_id, "rung": rung,
                             "model": author, "adopter_model": adopter, "faithful": faithful,
                             "author_compile_outcome": author_outcome,
                             "author2_compile_outcome": author2_outcome,
                             "adopter_compile_outcome": adopter_outcome}) + "\n")


_HAIKU, _SONNET = "claude-haiku-4-5-20251001", "claude-sonnet-4-6"


def test_score_pools_self_and_cross(tmp_path) -> None:
    """Two author-model compiles (self) + one adopter-model compile (cross), all
    equivalent: self is 1 pair, cross is 2 pairs, every cell 100%."""
    _write_doc(tmp_path, "echo", "a" * 16, author=_HAIKU, adopter=_SONNET, faithful=True,
               author_src=GOOD, author2_src=GOOD, adopter_src=GOOD)
    results = score_authored_session(tmp_path, workers=1)
    assert len(results) == 1
    r = results[0]
    assert r.rung == "echo"
    assert r.func_self == r.repr_self == (1, 1)      # C(2,1) self pair
    assert r.func_cross == r.repr_cross == (2, 2)    # 2 author x 1 adopter cross pairs


def test_score_separates_good_self_from_broken_cross(tmp_path) -> None:
    """A divergent adopter drops cross to 0 while self stays perfect — exactly the
    self >= cross signal Table IV is meant to surface."""
    _write_doc(tmp_path, "echo", "b" * 16, author=_HAIKU, adopter=_SONNET, faithful=True,
               author_src=GOOD, author2_src=GOOD, adopter_src=BROKEN_BEHAVIOUR)
    r = score_authored_session(tmp_path, workers=1)[0]
    assert r.repr_self == (1, 1) and r.func_self == (1, 1)
    assert r.repr_cross == (0, 2) and r.func_cross == (0, 2)


def test_faithful_only_filters_unfaithful_docs(tmp_path) -> None:
    _write_doc(tmp_path, "echo", "c" * 16, author=_HAIKU, adopter=_SONNET, faithful=False,
               author_src=GOOD, author2_src=GOOD, adopter_src=GOOD)
    assert score_authored_session(tmp_path, workers=1, faithful_only=True) == []
    assert score_authored_session(tmp_path, workers=1, faithful_only=False)  # scored when off


def test_vector_fail_compile_is_excluded(tmp_path) -> None:
    """A compile the run recorded as vector-fail is dropped even if its source is
    on disk: here the adopter is vector-fail, so no cross pair survives while the
    two OK author compiles still form the self pair."""
    _write_doc(tmp_path, "echo", "e" * 16, author=_HAIKU, adopter=_SONNET, faithful=True,
               author_src=GOOD, author2_src=GOOD, adopter_src=GOOD,
               adopter_outcome="compile_vector_fail")
    r = score_authored_session(tmp_path, workers=1)[0]
    assert r.func_self == r.repr_self == (1, 1)    # OK author compiles still paired
    assert r.func_cross == r.repr_cross == (0, 0)  # vector-fail adopter excluded


def test_doc_with_one_compile_is_skipped(tmp_path) -> None:
    """A document whose second author + adopter compiles both failed (absent
    files) has no pair to score and is dropped, not counted as a failure."""
    base = tmp_path / "authored" / "echo"
    base.mkdir(parents=True)
    (base / ("d" * 16 + ".md")).write_text(get_spec("echo").md_text, encoding="utf-8")
    (base / ("d" * 16 + ".author.py")).write_text(GOOD, encoding="utf-8")
    with open(tmp_path / "runs.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"arm": "authoring", "run_id": "d" * 16, "rung": "echo",
                             "model": _HAIKU, "adopter_model": _SONNET, "faithful": True,
                             "author_compile_outcome": "ok",
                             "author2_compile_outcome": "compile_load_fail",
                             "adopter_compile_outcome": "compile_load_fail"}) + "\n")
    assert score_authored_session(tmp_path, workers=1) == []
