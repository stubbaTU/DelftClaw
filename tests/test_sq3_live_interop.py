"""Spike + harness tests for the live two-node SQ3 interop measurement.

The headline test proves the whole integration: two independently "compiled"
echo communities run as real IPv8 nodes on the mock internet, and a message
sent A->B drives B's generated handler, whose reply drives A's handler — all
through real ``ez_send`` dispatch and serialization. If this passes, the live
behavioral-conformance approach is viable.
"""

from __future__ import annotations

import pytest

from _live_llm import compile_source
from experiments.fixtures import get_spec
from experiments.live_interop import TwoNodeNetwork, load_overlay


def _message(parsed, name: str):
    return next(m for m in parsed.messages if m.name == name)


@pytest.mark.asyncio
async def test_echo_pair_round_trips_over_live_ipv8() -> None:
    """A->ECHO_REQUEST drives B's handler; B's ECHO_RESPONSE drives A's handler.

    Both sides are a REAL live compilation of the echo spec (skips without an
    endpoint). After one send+settle, the initiator's ``received_responses``
    must hold the echoed-with-bang string.
    """
    spec = get_spec("echo")
    cid = bytes.fromhex(spec.community_id_hex)
    source = compile_source(spec.md_text)
    a = load_overlay(source, cid)
    b = load_overlay(source, cid)

    async with TwoNodeNetwork(a, b, cid) as net:
        echo_request = _message(spec.parsed, "ECHO_REQUEST")
        await net.send(0, 1, echo_request, {"payload": "hi"})

        # A initiated; B echoed; the reply came back to A's received_responses.
        assert net.state(0, "received_responses") == ["hi!"]
        # B never received an ECHO_RESPONSE, so its own cache stays empty.
        assert net.state(1, "received_responses") == []


@pytest.mark.asyncio
async def test_load_overlay_falls_back_to_generated_community_name() -> None:
    """A source whose community_id doesn't match still resolves via the
    ``GeneratedCommunity`` class name (compiler's own fallback rule)."""
    spec = get_spec("echo")
    source = compile_source(spec.md_text)
    wrong_cid = bytes(20)  # all-zero, will not match the echo community_id
    loaded = load_overlay(source, wrong_cid)
    assert loaded.community_cls.__name__ == "GeneratedCommunity"
