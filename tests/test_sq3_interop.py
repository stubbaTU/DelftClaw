"""Tests for ``sq3.interop`` — pairwise cross-roundtrip + pair sampling.

The interop arm is the load-bearing measurement in SQ3: given two LLM-emitted
sources for the same spec, does the wire format agree byte-for-byte under the
spec's own test vectors? These tests pin the contract using deterministic
stub sources so a regression in the encoding allowlist (or in
``_payload_class_for``) shows up here before it shows up in a live run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from protocol.compiler import parse_md
from experiments.interop import pair_interoperates, sample_pairs


REPO_ROOT = Path(__file__).resolve().parent.parent


def _echo_source(impl_tweak: str = "") -> str:
    """A schema-conformant generated source for echo_overlay.md.

    Optional ``impl_tweak`` rewrites a fragment of the source so callers can
    produce a wire-MISMATCHED variant (e.g. swap an encoding's format token)
    while keeping the rest valid Python that survives the sandbox.
    """
    src = (
        "from ipv8.community import Community, CommunitySettings\n"
        "from ipv8.lazy_community import lazy_wrapper\n"
        "from ipv8.messaging.lazy_payload import VariablePayload, vp_compile\n"
        "from ipv8.peer import Peer\n"
        "from ipv8.peerdiscovery.network import PeerObserver\n"
        "\n"
        "@vp_compile\n"
        "class EchoRequestPayload(VariablePayload):\n"
        "    msg_id = 1\n"
        '    format_list = ["varlenH"]\n'
        '    names = ["payload"]\n'
        "\n"
        "@vp_compile\n"
        "class EchoResponsePayload(VariablePayload):\n"
        "    msg_id = 2\n"
        '    format_list = ["varlenH"]\n'
        '    names = ["payload"]\n'
        "\n"
        "class GeneratedCommunity(Community, PeerObserver):\n"
        '    community_id = bytes.fromhex("cb34767cf5594a303df692d0eca46d8cd022a31a")\n'
        "    def __init__(self, settings: CommunitySettings) -> None:\n"
        "        super().__init__(settings)\n"
        "        self.received_responses = []\n"
        "    def started(self) -> None:\n"
        "        self.network.add_peer_observer(self)\n"
        "    def on_peer_added(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    def on_peer_removed(self, peer: Peer) -> None:\n"
        "        pass\n"
        "    @lazy_wrapper(EchoRequestPayload)\n"
        "    def on_echo_request(self, peer, payload):\n"
        "        pass\n"
        "    @lazy_wrapper(EchoResponsePayload)\n"
        "    def on_echo_response(self, peer, payload):\n"
        "        pass\n"
    )
    if impl_tweak:
        src = src.replace(*impl_tweak.split("|", 1))
    return src


@pytest.fixture
def echo_spec():
    return parse_md((REPO_ROOT / "protocol" / "examples" / "echo_overlay.md").read_text(encoding="utf-8"))


def test_pair_interoperates_self_pairing_succeeds(echo_spec):
    """Two byte-identical sources MUST interoperate — that's the boring
    baseline that proves the harness loop works at all."""
    source = _echo_source()
    result = pair_interoperates(source, source, echo_spec)
    assert result.overall_pass is True
    # Each of the 3+3 echo test vectors round-trips both ways.
    assert len(result.per_vector) == len(echo_spec.test_vectors) * 2


def test_pair_interoperates_distinct_but_equivalent_sources_succeed(echo_spec):
    """Two sources that differ in irrelevant detail (e.g. a no-op method
    rename) but produce wire-identical payload classes MUST interoperate.
    This is what SQ3 hopes the substrate delivers in the cross-LLM case."""
    a = _echo_source()
    # Swap a method body to confirm semantic-but-not-wire differences are OK.
    b = _echo_source(impl_tweak="def on_echo_request(self, peer, payload):\n        pass|def on_echo_request(self, peer, payload):\n        return None")
    assert a != b
    result = pair_interoperates(a, b, echo_spec)
    assert result.overall_pass is True


def test_pair_interoperates_wire_mismatch_fails(echo_spec):
    """A source whose format_list differs MUST NOT interoperate. We swap
    EchoResponsePayload's format from varlenH to uint8 — the wire byte
    layout diverges, decode produces wrong fields. This is the principal
    negative case the harness has to catch reliably."""
    a = _echo_source()
    b = _echo_source(
        impl_tweak='@vp_compile\nclass EchoResponsePayload(VariablePayload):\n    msg_id = 2\n    format_list = ["varlenH"]\n    names = ["payload"]|'
        '@vp_compile\nclass EchoResponsePayload(VariablePayload):\n    msg_id = 2\n    format_list = ["B"]\n    names = ["payload"]'
    )
    result = pair_interoperates(a, b, echo_spec)
    assert result.overall_pass is False
    # At least one ECHO_RESPONSE vector must surface a mismatch.
    failures = [o for o in result.per_vector if not o.ok]
    assert failures, "expected at least one per-vector failure"


# ---------------------------------------------------------------------------
# sample_pairs — coverage + size invariants
# ---------------------------------------------------------------------------

def test_sample_pairs_zero_or_one_returns_empty():
    assert sample_pairs(0) == []
    assert sample_pairs(1) == []


def test_sample_pairs_covers_every_index_for_small_n():
    """Coverage invariant from the doc: every surviving compile appears in
    at least one returned pair, so the pairs graph is connected."""
    pairs = sample_pairs(n_compiles=5, k=4, seed=42)
    seen: set[int] = set()
    for a, b in pairs:
        seen.add(a)
        seen.add(b)
    assert seen == {0, 1, 2, 3, 4}


def test_sample_pairs_caps_at_unique_pairs():
    """K larger than n*(n-1)/2 returns every unique pair, no duplicates."""
    pairs = sample_pairs(n_compiles=4, k=100, seed=0)
    expected_n = 4 * 3 // 2
    assert len(pairs) == expected_n
    assert len(set(pairs)) == expected_n


def test_sample_pairs_deterministic_with_seed():
    a = sample_pairs(n_compiles=10, k=15, seed=7)
    b = sample_pairs(n_compiles=10, k=15, seed=7)
    assert a == b


def test_sample_pairs_no_self_pairs():
    for a, b in sample_pairs(n_compiles=8, k=20, seed=1):
        assert a != b
