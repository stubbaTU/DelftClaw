"""Compile pipeline smoke tests using a stub LLM client.

These exercise the full ``compile_overlay`` flow without a live LLM:

  - parse_md / canonicalize_md round-trip + community_id stability
  - schema validation rejects malformed descriptors
  - sandbox AST whitelist rejects forbidden imports / builtins
  - end-to-end compile of ``echo_overlay.md`` against a hand-authored
    stub source produces a working IPv8 Community class with passing
    test vectors
"""

from __future__ import annotations

import pytest

from protocol import (
    ProtocolCompileError,
    SandboxError,
    StubLLMClient,
    canonicalize_md,
    community_id_from_md,
    compile_overlay,
    parse_md,
    safe_exec,
    validate_ast,
)
from protocol.examples.echo_overlay_stub import ECHO_OVERLAY_SOURCE


ECHO_MD = open(
    __file__.replace("tests/test_protocol_compiler.py", "protocol/examples/echo_overlay.md")
).read()
ECHO_CID = community_id_from_md(ECHO_MD).hex()


def _stub_for_echo() -> StubLLMClient:
    fenced = "```python\n" + ECHO_OVERLAY_SOURCE + "```"
    return StubLLMClient(sources={ECHO_CID: fenced})


# ---------------------------------------------------------------------------
# Canonicalization + community_id derivation
# ---------------------------------------------------------------------------

def test_canonicalize_strips_trailing_whitespace_and_crlf():
    raw = "# Identity\r\n  \n- name: x  \n\n\n"
    canon = canonicalize_md(raw)
    assert canon == b"# Identity\n\n- name: x"


def test_community_id_is_stable_across_call():
    a = community_id_from_md(ECHO_MD)
    b = community_id_from_md(ECHO_MD)
    assert a == b
    assert len(a) == 20


def test_community_id_changes_with_content():
    a = community_id_from_md(ECHO_MD)
    b = community_id_from_md(ECHO_MD + "\n# Footer")
    assert a != b


# ---------------------------------------------------------------------------
# parse_md
# ---------------------------------------------------------------------------

def test_parse_echo_overlay_yields_two_messages():
    parsed = parse_md(ECHO_MD)
    assert parsed.identity["name"] == "echo"
    assert [m.name for m in parsed.messages] == ["ECHO_REQUEST", "ECHO_RESPONSE"]
    assert parsed.messages[0].msg_id == 1
    assert parsed.messages[1].msg_id == 2
    assert [f.name for f in parsed.messages[0].fields] == ["payload"]
    assert parsed.messages[0].fields[0].encoding == "varlenH-utf8"


def test_parse_collects_test_vectors():
    parsed = parse_md(ECHO_MD)
    assert len(parsed.test_vectors) == 6
    msg_names = {tv.message for tv in parsed.test_vectors}
    assert msg_names == {"ECHO_REQUEST", "ECHO_RESPONSE"}


def test_parse_rejects_missing_required_section():
    md = "# Identity\n- name: foo\n- version: 1.0.0\n- description: x\n"
    with pytest.raises(ProtocolCompileError, match="missing required sections"):
        parse_md(md)


def test_parse_rejects_unknown_encoding():
    md = ECHO_MD.replace("varlenH-utf8", "made-up-encoding")
    with pytest.raises(ProtocolCompileError, match="encoding"):
        parse_md(md)


def test_parse_rejects_duplicate_msg_id():
    md = ECHO_MD.replace("msg_id: 2", "msg_id: 1")
    with pytest.raises(ProtocolCompileError, match="duplicate msg_id"):
        parse_md(md)


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

def test_sandbox_rejects_forbidden_import():
    with pytest.raises(SandboxError, match="forbidden import"):
        validate_ast("import os\n")


def test_sandbox_rejects_eval_call():
    with pytest.raises(SandboxError, match="eval"):
        validate_ast("x = eval('1+1')\n")


def test_sandbox_rejects_dunder_attribute():
    with pytest.raises(SandboxError, match="__class__"):
        validate_ast("def f(o): return o.__class__\n")


def test_sandbox_rejects_with_statement():
    with pytest.raises(SandboxError, match="'with'"):
        validate_ast("with open('/tmp/x') as f: pass\n")


def test_sandbox_allows_ipv8_imports():
    src = "from ipv8.community import Community\nclass X(Community): pass\n"
    safe_exec(src)  # must not raise


# ---------------------------------------------------------------------------
# End-to-end compile
# ---------------------------------------------------------------------------

def test_compile_echo_overlay_produces_working_community_class():
    compiled = compile_overlay(ECHO_MD, _stub_for_echo())
    assert compiled.community_id.hex() == ECHO_CID
    assert compiled.community_class.__name__ == "GeneratedCommunity"
    assert set(compiled.payload_classes) == {"ECHO_REQUEST", "ECHO_RESPONSE"}


def test_compile_rejects_when_generated_class_has_wrong_id():
    bad_source = ECHO_OVERLAY_SOURCE.replace(ECHO_CID, "00" * 20)
    stub = StubLLMClient(sources={ECHO_CID: "```python\n" + bad_source + "```"})
    with pytest.raises(ProtocolCompileError, match="community_id mismatch"):
        compile_overlay(ECHO_MD, stub)


def test_compile_rejects_when_test_vector_fails():
    # Inject a wrong msg_id into the generated source so the payload
    # class encodes differently than the descriptor's vectors expect.
    # The simplest way: corrupt the format_list to produce different bytes.
    bad = ECHO_OVERLAY_SOURCE.replace('format_list = ["varlenH"]',
                                       'format_list = ["B"]')
    stub = StubLLMClient(sources={ECHO_CID: "```python\n" + bad + "```"})
    with pytest.raises(ProtocolCompileError):
        compile_overlay(ECHO_MD, stub)
