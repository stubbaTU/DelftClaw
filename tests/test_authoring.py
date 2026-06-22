"""Offline tests for SQ3 Flow-B document authoring (``sq3.authoring``).

The full green chain (author -> compile author+adopter -> adoption interop) is
validated against the real LLM by ``python -m sq3.cli run``. These tests use stub
clients to exercise the harness *logic* with no network: argument parsing, the
two task-type prompts, and ``author_document``'s success/failure folding.
"""

from __future__ import annotations

import json

import pytest

from experiments.authoring import (
    AuthoringParseError,
    DESCRIPTIONS,
    author_document,
    build_authoring_prompt,
    build_evolution_prompt,
    parse_authoring_args,
)
from experiments.fixtures import get_spec


# ---------------------------------------------------------------------------
# parse_authoring_args
# ---------------------------------------------------------------------------

def test_parse_valid():
    raw = ('{"name":"x","version":"1.0.0","messages":'
           '[{"name":"M","msg_id":1,"fields":[],"handler":"h"}]}')
    assert parse_authoring_args(raw)["name"] == "x"


def test_parse_tolerates_code_fences_and_prose():
    raw = ('Here is the protocol:\n```json\n'
           '{"name":"y","messages":[{"name":"M","msg_id":1,"fields":[]}]}\n```\n')
    assert parse_authoring_args(raw)["name"] == "y"


@pytest.mark.parametrize("raw", [
    "not json at all",
    '{"messages":[{"name":"M","msg_id":1,"fields":[]}]}',  # missing name
    '{"name":"x"}',                                          # missing messages
    '{"name":"x","messages":[]}',                            # empty messages
    '{"name":"x","messages":"nope"}',                        # messages not a list
])
def test_parse_rejects_bad(raw):
    with pytest.raises(AuthoringParseError):
        parse_authoring_args(raw)


# ---------------------------------------------------------------------------
# prompts
# ---------------------------------------------------------------------------

def test_genesis_prompt_carries_description():
    assert "echo" in build_authoring_prompt(DESCRIPTIONS["echo"]).lower()


def test_evolution_prompt_renders_base_and_asks_one_field():
    p = build_evolution_prompt(get_spec("payment").parsed)
    assert "PAYMENT_REQUEST" in p
    assert "ONE" in p
    assert "1.1.0" in p


# ---------------------------------------------------------------------------
# author_document (stub clients)
# ---------------------------------------------------------------------------

class StubClient:
    """Returns a canned authoring response regardless of prompt."""

    def __init__(self, author_response: str) -> None:
        self._author = author_response

    def complete(self, system: str, user: str, *, max_tokens: int = 4096) -> str:
        return self._author


_GOOD_ARGS = json.dumps({
    "name": "ping", "version": "1.0.0", "description": "d", "change_summary": "c",
    "messages": [{
        "name": "PING", "msg_id": 1,
        "fields": [{"name": "text", "encoding": "varlenH-utf8", "description": "t"}],
        "handler": "append the text to received",
    }],
    "runtime_state": [{"name": "received", "type": "list[dict]", "description": "r"}],
    "samples": {"PING": {"text": "hi"}},
})


def test_author_document_genesis_succeeds():
    doc = author_document("echo", StubClient(_GOOD_ARGS))
    assert doc.ok
    assert doc.name == "ping"
    assert doc.parsed is not None and doc.task_type == "genesis"


def test_author_document_garbage_folds_to_not_ok():
    doc = author_document("echo", StubClient("garbage, not json"))
    assert not doc.ok
    assert doc.error and doc.parsed is None


def test_author_document_bad_encoding_folds_to_not_ok():
    bad = json.dumps({"name": "z", "messages": [{
        "name": "M", "msg_id": 1,
        "fields": [{"name": "f", "encoding": "not-an-encoding", "description": ""}],
        "handler": "h"}]})
    doc = author_document("echo", StubClient(bad))
    assert not doc.ok


def test_author_document_evolution_injects_base_identity():
    """Evolution forces the base name + 1.1.0 lineage even though the args name
    something else, so author still succeeds and takes the base identity."""
    base = get_spec("payment")
    doc = author_document(
        "payment", StubClient(_GOOD_ARGS), task_type="evolution",
        base_parsed=base.parsed, base_community_id_hex=base.community_id_hex)
    assert doc.ok
    assert doc.name == "payment_request"     # base name injected
    assert doc.task_type == "evolution"
