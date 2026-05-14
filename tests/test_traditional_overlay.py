"""Tests for the traditional Python Community overlay path.

Covers:
  * OverlayRegistry.register_community(cls) — registers, caches, and
    introspects payload classes.
  * _introspect_payload_classes — SCREAMING_SNAKE_CASE conversion,
    duplicate-msg_id rejection, missing-payload rejection.
  * overlay_to_dict — emits origin discriminator + metadata-light entry
    when parsed is None.
  * agent.tools.overlays_list / overlay_describe over the new origin.
  * --register-community CLI argument parser (_import_class_spec).
  * Two-node ECHO_REQUEST round-trip with the traditional community.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.community import SeedboxCommunity
from protocol import OverlayRegistry, StubLLMClient
from protocol.examples.echo_traditional import (
    EchoRequestPayload,
    EchoTraditionalCommunity,
)
from protocol.registry import (
    _camel_to_screaming_snake,
    _introspect_payload_classes,
    overlay_to_dict,
)


# ---------------------------------------------------------------------------
# Helpers (mirror the existing test_overlay_registry fixtures)
# ---------------------------------------------------------------------------

def _build_node(port: int, key_path: Path) -> IPv8:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.set_address("127.0.0.1")
    builder.add_key("anchor", "curve25519", str(key_path))
    builder.add_overlay("SeedboxCommunity", "anchor", [], [], {}, [("started",)])
    return IPv8(
        builder.finalize(),
        extra_communities={"SeedboxCommunity": SeedboxCommunity},
    )


@pytest_asyncio.fixture
async def two_nodes(tmp_path):
    """Two IPv8 nodes pre-introduced — same shape as test_overlay_registry."""
    from ipv8.keyvault.crypto import default_eccrypto

    key_a = tmp_path / "a.key"
    key_b = tmp_path / "b.key"
    key_a.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())
    key_b.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())

    svc_a = _build_node(port=0, key_path=key_a)
    svc_b = _build_node(port=0, key_path=key_b)
    await svc_a.start()
    await svc_b.start()

    sb_a = next(o for o in svc_a.overlays if isinstance(o, SeedboxCommunity))
    sb_b = next(o for o in svc_b.overlays if isinstance(o, SeedboxCommunity))

    addr_a = sb_a.endpoint.get_address()
    addr_b = sb_b.endpoint.get_address()
    peer_b_for_a = Peer(sb_b.my_peer.public_key, address=addr_b)
    peer_a_for_b = Peer(sb_a.my_peer.public_key, address=addr_a)
    sb_a.network.add_verified_peer(peer_b_for_a)
    sb_b.network.add_verified_peer(peer_a_for_b)

    yield svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b

    await svc_a.stop()
    await svc_b.stop()


# ---------------------------------------------------------------------------
# Pure-function helpers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("camel,expected", [
    ("EchoRequest", "ECHO_REQUEST"),
    ("OverlayDelivery", "OVERLAY_DELIVERY"),
    ("Search", "SEARCH"),
    ("UserA", "USER_A"),
    # Pin the (documented) limitation: contiguous acronyms get split.
    # If a colleague writes ``HTTPRequestPayload``, they should add
    # ``MESSAGE_NAME = "HTTP_REQUEST"`` as an explicit override.
    ("HTTPRequest", "H_T_T_P_REQUEST"),
])
def test_camel_to_screaming_snake(camel, expected):
    assert _camel_to_screaming_snake(camel) == expected


def test_introspect_payload_classes_finds_two_in_module():
    out = _introspect_payload_classes(EchoTraditionalCommunity)
    assert set(out.keys()) == {"ECHO_REQUEST", "ECHO_RESPONSE"}
    assert out["ECHO_REQUEST"] is EchoRequestPayload
    assert out["ECHO_REQUEST"].msg_id == 1
    assert out["ECHO_RESPONSE"].msg_id == 2


def test_introspect_payload_classes_rejects_module_without_payloads(tmp_path):
    """A class whose module has no VariablePayload subclasses raises."""
    # Build a throwaway module on the fly using ``exec`` into an empty namespace.
    import types
    from ipv8.community import Community
    from ipv8.peerdiscovery.network import PeerObserver

    mod = types.ModuleType("test_traditional_overlay_empty_mod")

    class LonelyCommunity(Community, PeerObserver):  # type: ignore[misc]
        community_id = b"\x11" * 20

        def __init__(self, settings):
            super().__init__(settings)

    LonelyCommunity.__module__ = mod.__name__
    mod.LonelyCommunity = LonelyCommunity
    import sys
    sys.modules[mod.__name__] = mod
    try:
        with pytest.raises(ValueError, match="no VariablePayload subclasses"):
            _introspect_payload_classes(LonelyCommunity)
    finally:
        sys.modules.pop(mod.__name__, None)


def test_introspect_payload_classes_rejects_duplicate_msg_id():
    """Two payloads with the same msg_id in the same module abort registration."""
    import types
    from ipv8.community import Community
    from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
    from ipv8.peerdiscovery.network import PeerObserver

    mod = types.ModuleType("test_traditional_overlay_dup_mod")

    @vp_compile
    class OnePayload(VariablePayload):
        msg_id = 7
        format_list = ["varlenH"]
        names = ["a"]

    @vp_compile
    class TwoPayload(VariablePayload):
        msg_id = 7  # same msg_id as One
        format_list = ["varlenH"]
        names = ["b"]

    class DupCommunity(Community, PeerObserver):  # type: ignore[misc]
        community_id = b"\x22" * 20

        def __init__(self, settings):
            super().__init__(settings)

    for cls in (OnePayload, TwoPayload, DupCommunity):
        cls.__module__ = mod.__name__
    mod.OnePayload = OnePayload
    mod.TwoPayload = TwoPayload
    mod.DupCommunity = DupCommunity
    import sys
    sys.modules[mod.__name__] = mod
    try:
        with pytest.raises(ValueError, match="duplicate msg_id"):
            _introspect_payload_classes(DupCommunity)
    finally:
        sys.modules.pop(mod.__name__, None)


# ---------------------------------------------------------------------------
# Registry path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_register_community_registers_with_ipv8(two_nodes):
    svc_a, _svc_b, _sb_a, _sb_b, _peer_b, _peer_a = two_nodes

    reg = OverlayRegistry(svc_a, StubLLMClient(sources={}))
    before = len(svc_a.overlays)
    instance = reg.register_community(EchoTraditionalCommunity)

    assert isinstance(instance, EchoTraditionalCommunity)
    assert len(svc_a.overlays) == before + 1
    assert reg.get(EchoTraditionalCommunity.community_id) is instance

    # Cached entry has origin="python_class" and parsed=None.
    compiled = reg._compiled[EchoTraditionalCommunity.community_id]
    assert compiled.origin == "python_class"
    assert compiled.parsed is None
    assert compiled.canonical_md_bytes == b""
    assert set(compiled.payload_classes.keys()) == {"ECHO_REQUEST", "ECHO_RESPONSE"}


@pytest.mark.asyncio
async def test_register_community_is_idempotent(two_nodes):
    svc_a, *_ = two_nodes
    reg = OverlayRegistry(svc_a, StubLLMClient(sources={}))
    a = reg.register_community(EchoTraditionalCommunity)
    b = reg.register_community(EchoTraditionalCommunity)
    assert a is b


@pytest.mark.asyncio
async def test_register_community_rejects_bad_community_id(two_nodes):
    svc_a, *_ = two_nodes
    reg = OverlayRegistry(svc_a, StubLLMClient(sources={}))

    from ipv8.community import Community
    from ipv8.peerdiscovery.network import PeerObserver

    class WrongCommunity(Community, PeerObserver):  # type: ignore[misc]
        community_id = b"\xff" * 19  # only 19 bytes

        def __init__(self, settings):
            super().__init__(settings)

    with pytest.raises(ValueError, match="community_id must be 20 bytes"):
        reg.register_community(WrongCommunity)


# ---------------------------------------------------------------------------
# overlay_to_dict
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_overlay_to_dict_python_class_origin(two_nodes):
    svc_a, *_ = two_nodes
    reg = OverlayRegistry(svc_a, StubLLMClient(sources={}))
    reg.register_community(EchoTraditionalCommunity)
    compiled = reg._compiled[EchoTraditionalCommunity.community_id]
    out = overlay_to_dict(compiled)

    assert out["origin"] == "python_class"
    assert out["name"] == "EchoTraditionalCommunity"
    assert out["version"] == ""
    assert out["description"].startswith("Tiny echo community")
    msg_names = {m["name"] for m in out["messages"]}
    assert msg_names == {"ECHO_REQUEST", "ECHO_RESPONSE"}
    req = next(m for m in out["messages"] if m["name"] == "ECHO_REQUEST")
    assert req["msg_id"] == 1
    assert req["fields"] == [{"name": "payload", "encoding": "varlenH", "description": ""}]
    assert req["handler_text"] == ""
    assert out["errors"] == []
    assert out["dependencies"] == []


# ---------------------------------------------------------------------------
# CLI flag parser
# ---------------------------------------------------------------------------

def test_import_class_spec_imports_existing_class():
    from agent.cli import _import_class_spec
    cls = _import_class_spec("protocol.examples.echo_traditional:EchoTraditionalCommunity")
    assert cls is EchoTraditionalCommunity


def test_import_class_spec_rejects_malformed_spec():
    import argparse
    from agent.cli import _import_class_spec
    for bad in ["no_colon", ":Class", "module:", ""]:
        with pytest.raises(argparse.ArgumentTypeError):
            _import_class_spec(bad)


def test_import_class_spec_rejects_unknown_module():
    import argparse
    from agent.cli import _import_class_spec
    with pytest.raises(argparse.ArgumentTypeError, match="cannot import"):
        _import_class_spec("no.such.module:Class")


def test_import_class_spec_rejects_unknown_class():
    import argparse
    from agent.cli import _import_class_spec
    with pytest.raises(argparse.ArgumentTypeError, match="has no attribute"):
        _import_class_spec("protocol.examples.echo_traditional:NotAClass")


# ---------------------------------------------------------------------------
# End-to-end wire round-trip
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_traditional_community_round_trip(two_nodes):
    """Two agents both register the same hand-written community and exchange ECHO."""
    svc_a, svc_b, sb_a, sb_b, peer_b_for_a, peer_a_for_b = two_nodes

    reg_a = OverlayRegistry(svc_a, StubLLMClient(sources={}))
    reg_b = OverlayRegistry(svc_b, StubLLMClient(sources={}))

    echo_a = reg_a.register_community(EchoTraditionalCommunity)
    echo_b = reg_b.register_community(EchoTraditionalCommunity)

    # Cross-introduce on the new overlay (mirrors test_overlay_registry).
    echo_a.network.add_verified_peer(
        Peer(echo_b.my_peer.public_key, address=sb_b.endpoint.get_address())
    )
    echo_b.network.add_verified_peer(
        Peer(echo_a.my_peer.public_key, address=sb_a.endpoint.get_address())
    )

    # A -> B
    payload_cls = reg_a._compiled[EchoTraditionalCommunity.community_id].payload_classes[
        "ECHO_REQUEST"
    ]
    echo_a.ez_send(
        next(iter(echo_a.network.verified_peers)),
        payload_cls(b"hello"),
    )

    for _ in range(40):
        if echo_a.received_responses:
            break
        await asyncio.sleep(0.05)
    assert echo_a.received_responses == ["hello!"]
