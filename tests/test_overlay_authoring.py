"""Tests for deterministic overlay synthesis (agent.overlay_authoring).

The load-bearing property: a spec synthesized from structured field specs must
compile first-try through the real ``compile_overlay`` pipeline — including the
``# Test Vectors`` round-trip the compiler enforces. If ``compute_test_vectors``
disagreed by one byte with the serializer the compiler validates against, the
synthesized spec would be rejected. These tests pin that down without a live LLM
(an inline conformant implementation is fed via llm_source), so CI catches synthesis
drift even offline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.overlay_authoring import (
    OverlayAuthoringError,
    compute_test_vectors,
    synthesize_overlay_markdown,
)
from protocol import community_id_from_md, compile_overlay
from protocol.compiler import parse_md, validate_schema
from _live_llm import noop_llm


ANNOUNCE_MESSAGES = [{
    "name": "ANNOUNCE",
    "msg_id": 1,
    "fields": [
        {"name": "who", "encoding": "varlenH-utf8", "description": "announcer"},
        {"name": "filename", "encoding": "varlenH-utf8", "description": "file"},
        {"name": "size_bytes", "encoding": "uint32-be", "description": "bytes"},
    ],
    "handler": "On receipt, append {who, filename, size_bytes} to self.received_announcements.",
}]
ANNOUNCE_STATE = [{"name": "received_announcements", "type": "list[dict]", "description": "received"}]
ANNOUNCE_SAMPLES = {"ANNOUNCE": {"who": "fetcher_1", "filename": "calc.txt", "size_bytes": 382}}


def _announce_impl(cid_hex: str) -> str:
    """A conformant generated implementation for the ANNOUNCE overlay, so the
    compile pipeline can be exercised offline via llm_source (no live LLM)."""
    return (
        "```python\n"
        "from ipv8.community import Community, CommunitySettings\n"
        "from ipv8.lazy_community import lazy_wrapper\n"
        "from ipv8.messaging.lazy_payload import VariablePayload, vp_compile\n"
        "from ipv8.peer import Peer\n"
        "from ipv8.peerdiscovery.network import PeerObserver\n"
        "\n"
        "@vp_compile\n"
        "class AnnouncePayload(VariablePayload):\n"
        "    msg_id = 1\n"
        '    format_list = ["varlenH", "varlenH", "I"]\n'
        '    names = ["who", "filename", "size_bytes"]\n'
        "\n"
        "class GeneratedCommunity(Community, PeerObserver):\n"
        f'    community_id = bytes.fromhex("{cid_hex}")\n'
        "    def __init__(self, settings: CommunitySettings) -> None:\n"
        "        super().__init__(settings)\n"
        "        self.received_announcements = []\n"
        "        self.add_message_handler(AnnouncePayload, self.on_announce)\n"
        "    def started(self) -> None:\n"
        "        self.network.add_peer_observer(self)\n"
        "    def on_peer_added(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    def on_peer_removed(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    @lazy_wrapper(AnnouncePayload)\n"
        "    def on_announce(self, peer: Peer, payload: AnnouncePayload) -> None:\n"
        "        self.received_announcements.append({\n"
        '            "who": payload.who.decode("utf-8"),\n'
        '            "filename": payload.filename.decode("utf-8"),\n'
        '            "size_bytes": payload.size_bytes,\n'
        "        })\n"
        "```"
    )


def test_synthesized_spec_parses_and_validates():
    md = synthesize_overlay_markdown(
        name="download_announce", version="1.0.0",
        description="Announce a completed download to peers.",
        messages=ANNOUNCE_MESSAGES, runtime_state=ANNOUNCE_STATE,
        author_id="dclaw1abc", change_summary="Announce downloads",
        samples=ANNOUNCE_SAMPLES,
    )
    parsed = parse_md(md)
    validate_schema(parsed)
    assert parsed.identity["name"] == "download_announce"
    assert parsed.identity["author_id"] == "dclaw1abc"
    assert parsed.identity["change_summary"] == "Announce downloads"
    assert [m.name for m in parsed.messages] == ["ANNOUNCE"]
    assert [s.name for s in parsed.runtime_state] == ["received_announcements"]


def test_synthesized_spec_compiles_through_real_pipeline():
    md = synthesize_overlay_markdown(
        name="download_announce", version="1.0.0",
        description="Announce a completed download to peers.",
        messages=ANNOUNCE_MESSAGES, runtime_state=ANNOUNCE_STATE,
        samples=ANNOUNCE_SAMPLES,
    )
    cid_hex = community_id_from_md(md).hex()
    # Feed the inline conformant impl through llm_source (no live model).
    compiled = compile_overlay(md, noop_llm(), llm_source=_announce_impl(cid_hex))
    assert compiled.community_id.hex() == cid_hex
    assert "ANNOUNCE" in compiled.payload_classes


def test_compute_test_vectors_two_distinct_per_message():
    vectors = compute_test_vectors(ANNOUNCE_MESSAGES, ANNOUNCE_SAMPLES)
    assert set(vectors) == {"ANNOUNCE"}
    vs = vectors["ANNOUNCE"]
    assert len(vs) == 2
    # zero vector then populated; bytes differ; populated ends in 382 (0x017e).
    assert vs[0][1] != vs[1][1]
    assert vs[1][0]["size_bytes"] == 382
    assert vs[1][1].endswith("00017e")


def test_supersedes_carried_into_identity():
    pred = "a3455e9cec3b78bc281f1c495b0a08baa733833a"
    md = synthesize_overlay_markdown(
        name="download_announce", version="1.1.0", description="v2",
        messages=ANNOUNCE_MESSAGES, supersedes=pred,
        author_id="dclaw1abc", change_summary="adds a field",
    )
    parsed = parse_md(md)
    assert parsed.identity["supersedes"] == pred


def test_unsupported_encoding_rejected():
    bad = [{"name": "X", "msg_id": 1,
            "fields": [{"name": "f", "encoding": "float64", "description": ""}],
            "handler": "noop"}]
    with pytest.raises(OverlayAuthoringError):
        synthesize_overlay_markdown(name="x", version="1.0.0", description="x", messages=bad)


def test_no_messages_rejected():
    with pytest.raises(OverlayAuthoringError):
        synthesize_overlay_markdown(name="x", version="1.0.0", description="x", messages=[])


# ---------------------------------------------------------------------------
# Schema v1.1 ergonomic encodings — the synthesis path correctly converts
# hex-string samples for hash20/hash32 to raw bytes, so the produced .md
# compiles first-try. timestamp_unix is a pure naming alias and just rides
# the uint64-be path.
# ---------------------------------------------------------------------------

def test_compute_test_vectors_hash32_hex_sample_becomes_raw_bytes_on_wire():
    """A hash32 field with a 64-char hex-string sample produces a test vector
    whose bytes are exactly the 32-byte struct packing of that hex — proving
    the sample-coercion path uses bytes.fromhex(value) not value.encode()."""
    msgs = [{
        "name": "ANNOUNCE", "msg_id": 1,
        "fields": [
            {"name": "checksum", "encoding": "hash32", "description": "sha256"},
        ],
        "handler": "store",
    }]
    hex_sample = "4b" * 32   # 64 hex chars -> 32 raw bytes on the wire
    vectors = compute_test_vectors(
        msgs, samples={"ANNOUNCE": {"checksum": hex_sample}},
    )
    assert "ANNOUNCE" in vectors
    populated_hex = vectors["ANNOUNCE"][1][1]  # second vector = sample-based
    # Raw bytes on the wire are exactly the 32-byte hex decode, not the
    # 64-byte utf-8 encoding of the hex string.
    assert populated_hex == ("4b" * 32)
    assert len(populated_hex) == 64    # = 32 bytes * 2 hex chars
    # If the bug were still present, populated_hex would include the
    # utf-8 encoding of "4b4b4b...", which is 64 bytes -> 128 hex chars.


def test_compute_test_vectors_timestamp_unix_int_sample_packs_big_endian_uint64():
    """timestamp_unix is wire-identical to uint64-be; an int sample packs as
    8 bytes big-endian. This pins that the alias didn't accidentally route
    through a string-coercion branch."""
    msgs = [{
        "name": "ANNOUNCE", "msg_id": 1,
        "fields": [
            {"name": "completed_at", "encoding": "timestamp_unix", "description": "secs"},
        ],
        "handler": "store",
    }]
    vectors = compute_test_vectors(
        msgs, samples={"ANNOUNCE": {"completed_at": 1717000000}},
    )
    populated_hex = vectors["ANNOUNCE"][1][1]
    # 1717000000 = 0x66575740; big-endian uint64 = 8 bytes -> 16 hex chars,
    # zero-padded on the high side.
    assert populated_hex == "0000000066575740"


def test_compute_test_vectors_bytes20_with_raw_literal_unchanged():
    """Backwards-compat: pre-v1.1 bytes20 path with a Python bytes literal
    still works. No regression from the encoding-aware coercion."""
    msgs = [{
        "name": "ANNOUNCE", "msg_id": 1,
        "fields": [
            {"name": "payload", "encoding": "bytes20", "description": ""},
        ],
        "handler": "store",
    }]
    sample = b"\x07" * 20
    vectors = compute_test_vectors(msgs, samples={"ANNOUNCE": {"payload": sample}})
    populated_hex = vectors["ANNOUNCE"][1][1]
    assert populated_hex == sample.hex()


def test_synthesized_spec_with_hash20_field_round_trips_through_compiler():
    """The whole point of v1.1: a spec authored with hash20 + hex sample
    compiles cleanly through the real compile_overlay pipeline (which runs
    the test-vector round-trip we couldn't pass before). Uses a hand-matched
    stub source so no live LLM is needed."""
    msgs = [{
        "name": "ANNOUNCE", "msg_id": 1,
        "fields": [
            {"name": "who", "encoding": "varlenH-utf8", "description": "agent"},
            {"name": "digest", "encoding": "hash20", "description": "sha1"},
        ],
        "handler": "On receipt, append {who, digest_hex} to self.received_announcements.",
    }]
    state = [{"name": "received_announcements", "type": "list[dict]", "description": ""}]
    md = synthesize_overlay_markdown(
        name="hashed_announce", version="1.0.0",
        description="ANNOUNCE with SHA-1 integrity",
        messages=msgs, runtime_state=state,
        samples={"ANNOUNCE": {"who": "fetcher_1", "digest": "ab" * 20}},
    )
    cid_hex = community_id_from_md(md).hex()
    impl = (
        "```python\n"
        "from ipv8.community import Community, CommunitySettings\n"
        "from ipv8.lazy_community import lazy_wrapper\n"
        "from ipv8.messaging.lazy_payload import VariablePayload, vp_compile\n"
        "from ipv8.peer import Peer\n"
        "from ipv8.peerdiscovery.network import PeerObserver\n"
        "@vp_compile\n"
        "class AnnouncePayload(VariablePayload):\n"
        "    msg_id = 1\n"
        '    format_list = ["varlenH", "20s"]\n'
        '    names = ["who", "digest"]\n'
        "class GeneratedCommunity(Community, PeerObserver):\n"
        f'    community_id = bytes.fromhex("{cid_hex}")\n'
        "    def __init__(self, settings: CommunitySettings) -> None:\n"
        "        super().__init__(settings)\n"
        "        self.received_announcements = []\n"
        "        self.add_message_handler(AnnouncePayload, self.on_announce)\n"
        "    def started(self) -> None:\n"
        "        self.network.add_peer_observer(self)\n"
        "    def on_peer_added(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    def on_peer_removed(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    @lazy_wrapper(AnnouncePayload)\n"
        "    def on_announce(self, peer: Peer, payload: AnnouncePayload) -> None:\n"
        "        self.received_announcements.append({\n"
        '            "who": payload.who.decode("utf-8"),\n'
        '            "digest_hex": payload.digest.hex(),\n'
        "        })\n"
        "```"
    )
    compiled = compile_overlay(md, noop_llm(), llm_source=impl)
    assert compiled.parsed.identity["name"] == "hashed_announce"
