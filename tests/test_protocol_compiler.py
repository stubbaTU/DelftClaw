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

from pathlib import Path

import pytest

from protocol import (
    ProtocolCompileError,
    SandboxError,
    canonicalize_md,
    community_id_from_md,
    compile_overlay,
    parse_md,
    safe_exec,
    validate_ast,
)
from _live_llm import compile_source, noop_llm


REPO_ROOT = Path(__file__).resolve().parent.parent
ECHO_MD = (REPO_ROOT / "protocol" / "examples" / "echo_overlay.md").read_text(encoding="utf-8")
ECHO_CID = community_id_from_md(ECHO_MD).hex()


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
    # Real end-to-end compile via the live LLM (skips without an endpoint).
    source = compile_source(ECHO_MD)
    compiled = compile_overlay(ECHO_MD, noop_llm(), llm_source=source)
    assert compiled.community_id.hex() == ECHO_CID
    assert compiled.community_class.__name__ == "GeneratedCommunity"
    assert set(compiled.payload_classes) == {"ECHO_REQUEST", "ECHO_RESPONSE"}


def test_compile_rejects_when_generated_class_has_wrong_id():
    # Feed a source declaring the WRONG community_id via llm_source (no LLM):
    # the heartbeat fixture declares cid="00"*20, which cannot match _HEARTBEAT_MD.
    bad_source = _heartbeat_source("00" * 20)
    with pytest.raises(ProtocolCompileError, match="community_id mismatch"):
        compile_overlay(_HEARTBEAT_MD, noop_llm(), llm_source=bad_source)


def test_compile_rejects_when_test_vector_fails():
    # Corrupt the generated payload's format_list so it encodes differently
    # than the descriptor's vectors expect; fed via llm_source (no LLM).
    cid_hex = community_id_from_md(_HEARTBEAT_MD).hex()
    bad = _heartbeat_source(cid_hex).replace('format_list = ["I"]',
                                             'format_list = ["B"]')
    with pytest.raises(ProtocolCompileError):
        compile_overlay(_HEARTBEAT_MD, noop_llm(), llm_source=bad)


# ---------------------------------------------------------------------------
# # Tasks section (periodic register_task contract)
# ---------------------------------------------------------------------------

_HEARTBEAT_MD = """\
# Identity

- name: heartbeat
- version: 1.0.0
- description: Minimal overlay exercising the # Tasks section — periodic broadcast.
- lifecycle: peer-observer

# Messages

## HEARTBEAT

- msg_id: 1

| name | encoding | description |
|------|----------|-------------|
| counter | uint32-be | sender's monotonically increasing heartbeat counter |

### Handler

On receipt of HEARTBEAT, increment ``self.received_count`` and remember
the highest counter seen per peer.

# Runtime State

| name | type | description |
|------|------|-------------|
| received_count | int | total heartbeats received from any peer since boot |

# Tasks

| name | interval_s | handler | description |
|------|------------|---------|-------------|
| heartbeat_tick | 30 | _send_heartbeat | broadcast HEARTBEAT to every verified peer every 30s |

# Errors

| code | name | policy |
|------|------|--------|
| 1 | malformed_payload | drop |

# Dependencies

(none)

# Test Vectors

## HEARTBEAT

- fields: {"counter": 0}
  bytes: 00000000

- fields: {"counter": 1}
  bytes: 00000001
"""


_HEARTBEAT_SOURCE_OK = '''\
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer
from ipv8.peerdiscovery.network import PeerObserver


@vp_compile
class HeartbeatPayload(VariablePayload):
    msg_id = 1
    format_list = ["I"]
    names = ["counter"]


class GeneratedCommunity(Community, PeerObserver):
    community_id = bytes.fromhex("__CID__")

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.received_count = 0
        self.add_message_handler(HeartbeatPayload, self.on_heartbeat)
        self.register_task("heartbeat_tick", self._send_heartbeat, interval=30)

    def started(self) -> None:
        self.network.add_peer_observer(self)

    def on_peer_added(self, peer: Peer) -> None:
        pass

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    def _send_heartbeat(self) -> None:
        pass  # body intentionally empty for the test

    @lazy_wrapper(HeartbeatPayload)
    def on_heartbeat(self, peer: Peer, payload: HeartbeatPayload) -> None:
        self.received_count += 1
'''


def _heartbeat_source(cid_hex: str, source: str = _HEARTBEAT_SOURCE_OK) -> str:
    return "```python\n" + source.replace("__CID__", cid_hex) + "```"


def test_parse_tasks_section_captures_name_interval_handler():
    parsed = parse_md(_HEARTBEAT_MD)
    assert len(parsed.tasks) == 1
    t = parsed.tasks[0]
    assert t.name == "heartbeat_tick"
    assert t.interval_s == 30
    assert t.handler == "_send_heartbeat"


def test_parse_tasks_rejects_non_positive_interval():
    bad = _HEARTBEAT_MD.replace("| heartbeat_tick | 30 |", "| heartbeat_tick | 0 |")
    with pytest.raises(ProtocolCompileError, match="positive integer"):
        parse_md(bad)


def test_parse_tasks_rejects_non_int_interval():
    bad = _HEARTBEAT_MD.replace("| heartbeat_tick | 30 |", "| heartbeat_tick | thirty |")
    with pytest.raises(ProtocolCompileError, match="not an int"):
        parse_md(bad)


def test_parse_tasks_rejects_duplicate_handler():
    bad = _HEARTBEAT_MD.replace(
        "| heartbeat_tick | 30 | _send_heartbeat | broadcast HEARTBEAT to every verified peer every 30s |",
        "| heartbeat_tick | 30 | _send_heartbeat | broadcast HEARTBEAT to every verified peer every 30s |\n"
        "| sweep          | 60 | _send_heartbeat | reuse the same handler — should be rejected |",
    )
    with pytest.raises(ProtocolCompileError, match="duplicate handler"):
        parse_md(bad)


def test_compile_heartbeat_overlay_with_tasks_succeeds():
    # The post-LLM compile path is exercised offline by feeding a known-good
    # source via llm_source (no live model, no stub client).
    cid_hex = community_id_from_md(_HEARTBEAT_MD).hex()
    compiled = compile_overlay(_HEARTBEAT_MD, noop_llm(), llm_source=_heartbeat_source(cid_hex))
    assert compiled.parsed is not None
    assert len(compiled.parsed.tasks) == 1


def test_compile_rejects_when_register_task_call_is_missing():
    cid_hex = community_id_from_md(_HEARTBEAT_MD).hex()
    bad_source = _HEARTBEAT_SOURCE_OK.replace(
        'self.register_task("heartbeat_tick", self._send_heartbeat, interval=30)',
        "",
    )
    with pytest.raises(ProtocolCompileError, match="heartbeat_tick"):
        compile_overlay(_HEARTBEAT_MD, noop_llm(),
                        llm_source=_heartbeat_source(cid_hex, bad_source))


def test_compile_rejects_when_register_task_interval_disagrees_with_descriptor():
    cid_hex = community_id_from_md(_HEARTBEAT_MD).hex()
    bad_source = _HEARTBEAT_SOURCE_OK.replace("interval=30", "interval=15")
    with pytest.raises(ProtocolCompileError, match="heartbeat_tick"):
        compile_overlay(_HEARTBEAT_MD, noop_llm(),
                        llm_source=_heartbeat_source(cid_hex, bad_source))


def test_compile_rejects_when_task_handler_method_is_missing():
    cid_hex = community_id_from_md(_HEARTBEAT_MD).hex()
    # Remove the handler method definition entirely. The register_task
    # call still passes self._send_heartbeat as a reference, so AST
    # walking sees it; the structural check then asks the *class* for
    # the attribute and fails.
    bad_source = _HEARTBEAT_SOURCE_OK.replace(
        "    def _send_heartbeat(self) -> None:\n        pass  # body intentionally empty for the test\n\n",
        "",
    )
    with pytest.raises(ProtocolCompileError, match="_send_heartbeat"):
        compile_overlay(_HEARTBEAT_MD, noop_llm(),
                        llm_source=_heartbeat_source(cid_hex, bad_source))


# ---------------------------------------------------------------------------
# Schema v1.1 semantic encodings: hash20 / hash32 / timestamp_unix
# ---------------------------------------------------------------------------

def test_v1_1_encodings_registered_in_allowlist():
    """The three v1.1 ergonomic aliases are wire-identical to their primitives
    but distinct names in ALLOWED_ENCODINGS so they round-trip parsing."""
    from protocol.compiler import ALLOWED_ENCODINGS
    assert ALLOWED_ENCODINGS["hash20"] == "20s"
    assert ALLOWED_ENCODINGS["hash32"] == "32s"
    assert ALLOWED_ENCODINGS["timestamp_unix"] == "Q"


def test_coerce_hash20_hex_string_becomes_raw_bytes():
    """The load-bearing v1.1 behaviour: passing a 40-char hex string for a
    hash20 field is treated as raw bytes (bytes.fromhex), not utf-8. This is
    what eliminates the bytes-encoding boundary trip-up observed in deployed
    fetcher_2 v1.1 attempts."""
    from protocol.compiler import _coerce_field_value
    hex_str = "a3" * 20  # 40 hex chars
    out = _coerce_field_value(hex_str, encoding="hash20")
    assert isinstance(out, bytes)
    assert out == bytes.fromhex(hex_str)
    assert len(out) == 20


def test_coerce_hash32_hex_string_becomes_raw_bytes():
    from protocol.compiler import _coerce_field_value
    hex_str = "4b" * 32  # 64 hex chars
    out = _coerce_field_value(hex_str, encoding="hash32")
    assert out == bytes.fromhex(hex_str)
    assert len(out) == 32


def test_coerce_hash20_non_hex_string_raises_clean_compile_error():
    """A garbled sample produces a readable ProtocolCompileError that names
    the encoding and the expected hex-string shape."""
    from protocol.compiler import _coerce_field_value
    with pytest.raises(ProtocolCompileError, match="hash20.*hex"):
        _coerce_field_value("not-a-hash", encoding="hash20")


def test_coerce_without_encoding_preserves_pre_v1_1_string_utf8():
    """Backwards-compat: a string passed WITHOUT encoding context still goes
    through the original utf-8 branch (existing callers were varlenH-utf8 +
    test-vector paths)."""
    from protocol.compiler import _coerce_field_value
    assert _coerce_field_value("hello") == b"hello"
    assert _coerce_field_value("hello", encoding=None) == b"hello"


def test_coerce_bytes20_with_bytes_literal_unchanged():
    """The pre-v1.1 bytes20/bytes32 path is unchanged: raw Python bytes
    pass through verbatim, no hex parsing."""
    from protocol.compiler import _coerce_field_value
    payload = b"\x01" * 20
    assert _coerce_field_value(payload, encoding="bytes20") == payload


def test_v1_1_encodings_advertised_in_system_prompt():
    """The LLM-facing SYSTEM_PROMPT must list the new mappings so generated
    code uses the correct struct format tokens."""
    from protocol.compiler import SYSTEM_PROMPT
    assert 'hash20 -> "20s"' in SYSTEM_PROMPT
    assert 'hash32 -> "32s"' in SYSTEM_PROMPT
    assert 'timestamp_unix -> "Q"' in SYSTEM_PROMPT
