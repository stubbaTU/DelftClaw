"""Live-LLM compile smoke test for the overlay compiler.

Exercises the ONE path that ships but no other test covers: compiling a
descriptor through a *real* model via ``OpenAICompatibleClient``. Every other
compiler test feeds ``StubLLMClient`` hand-authored, conformant Python — which
silently bypasses ``compiler.SYSTEM_PROMPT`` entirely. The live demo compiles
through the real model (``OverlayRegistry(ipv8, agent.llm)``), so the prompt is
the untested load-bearing artifact this test guards.

It is the regression guard for the two prompt defects:

  * **payload-class naming** — a *compile-time* failure: the old prompt told the
    model to name the class ``<SCREAMING_SNAKE>Payload`` while the compiler looks
    up CamelCase ``<CamelCase>Payload``. Caught by ``test_live_compile_*``.
  * **msgpack import** — a *runtime* failure: the old prompt banned every import
    except the 5 ipv8 ones, but ``varlenH-msgpack`` handlers must
    ``import msgpack``. ``compile_overlay`` never executes handlers, so a missing
    import compiles clean and only blows up on the wire. Caught here two ways:
    a static ``import msgpack`` assertion on the generated source, and a real
    two-node SEARCH round-trip that actually runs the handler.

Skipped unless a compiler endpoint is configured and reachable. Reads
``LLM_BASE_URL``/``LLM_MODEL`` (the compiler endpoint, see deploy/watchdog.py).
Source ``configs/.env`` before running.
"""

from __future__ import annotations

import asyncio
import os
import socket
import urllib.error
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.configuration import ConfigBuilder
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.community import SeedboxCommunity, overlay_id
from protocol import (
    OpenAICompatibleClient,
    OverlayRegistry,
    community_id_from_md,
    compile_overlay,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "protocol" / "examples"
ECHO_MD = (EXAMPLES / "echo_overlay.md").read_text(encoding="utf-8")
CONTENT_MD = (EXAMPLES / "content_community.md").read_text(encoding="utf-8")
CONTENT_HASH = overlay_id(CONTENT_MD)

# Connection-class failures mean "endpoint not available" — skip, don't fail.
# (HTTPError is a URLError subclass, so an auth/4xx/5xx also skips.)
_CONN_ERRORS = (urllib.error.URLError, ConnectionError, TimeoutError, socket.timeout, OSError)


def _endpoint() -> tuple[str, str, str] | None:
    """Resolve (base_url, model, api_key) from env, or None if unconfigured."""
    base = os.environ.get("LLM_BASE_URL")
    model = os.environ.get("LLM_MODEL")
    if not base or not model:
        return None
    api_key = os.environ.get("LLM_API_KEY") or ""
    return base, model, api_key


_ENDPOINT = _endpoint()

pytestmark = pytest.mark.skipif(
    _ENDPOINT is None,
    reason=(
        "no compiler LLM endpoint configured — set "
        "LLM_BASE_URL/LLM_MODEL (source configs/.env)"
    ),
)


def _client(temperature: float = 0.0) -> OpenAICompatibleClient:
    base, model, api_key = _ENDPOINT  # type: ignore[misc]
    return OpenAICompatibleClient(
        base_url=base,
        model_id=model,
        api_key=api_key,
        temperature=temperature,
        timeout_s=120.0,
    )


def _compile_or_skip(md_text: str):
    """Compile via the real model; skip (not fail) if the endpoint is down."""
    try:
        return compile_overlay(md_text, _client())
    except _CONN_ERRORS as exc:
        pytest.skip(f"compiler endpoint unreachable: {exc}")


# ---------------------------------------------------------------------------
# Compile-time guards (catch the payload-naming defect)
# ---------------------------------------------------------------------------

def test_live_compile_echo():
    """The echo spec compiles end-to-end through a real model."""
    compiled = _compile_or_skip(ECHO_MD)
    assert compiled.community_id == community_id_from_md(ECHO_MD)
    assert set(compiled.payload_classes) == {"ECHO_REQUEST", "ECHO_RESPONSE"}


def test_live_compile_content_community():
    """The content_community spec compiles, and the generated source imports
    msgpack — the import the old prompt forbade but varlenH-msgpack needs."""
    compiled = _compile_or_skip(CONTENT_MD)
    assert compiled.community_id == CONTENT_HASH
    assert set(compiled.payload_classes) == {"SEARCH_REQUEST", "SEARCH_RESPONSE"}
    # varlenH-msgpack handler cannot work without this import; the gate can't
    # see it (handlers never run at compile time), so assert it statically.
    assert "msgpack" in compiled.source, (
        "generated content_community source does not reference msgpack — the "
        "varlenH-msgpack handler will NameError at runtime"
    )


# ---------------------------------------------------------------------------
# End-to-end round-trip (catches the msgpack runtime defect for real)
# ---------------------------------------------------------------------------

def _build_node(port: int, key_path: Path) -> IPv8:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.set_address("127.0.0.1")
    builder.add_key("anchor", "curve25519", str(key_path))
    builder.add_overlay("SeedboxCommunity", "anchor", [], [], {}, [("started",)])
    return IPv8(builder.finalize(), extra_communities={"SeedboxCommunity": SeedboxCommunity})


@pytest_asyncio.fixture
async def two_nodes(tmp_path):
    key_a = tmp_path / "a.key"
    key_b = tmp_path / "b.key"
    key_a.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())
    key_b.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())
    svc_a = _build_node(0, key_a)
    svc_b = _build_node(0, key_b)
    await svc_a.start()
    await svc_b.start()
    sb_a = next(o for o in svc_a.overlays if isinstance(o, SeedboxCommunity))
    sb_b = next(o for o in svc_b.overlays if isinstance(o, SeedboxCommunity))
    addr_a = sb_a.endpoint.get_address()
    addr_b = sb_b.endpoint.get_address()
    yield svc_a, svc_b, addr_a, addr_b
    await svc_a.stop()
    await svc_b.stop()


@pytest.mark.asyncio
async def test_live_content_search_round_trip(two_nodes):
    """A (real-LLM-compiled) content_community overlay actually serves a SEARCH.

    Both nodes compile the SAME descriptor through the real model; the handler
    runs msgpack on the wire. If the model produced a handler that can't reach
    msgpack, B's response_cache stays empty and this fails on timeout — the
    runtime symptom of the import defect.
    """
    svc_a, svc_b, addr_a, addr_b = two_nodes

    try:
        reg_a = OverlayRegistry(svc_a, _client())
        reg_b = OverlayRegistry(svc_b, _client())
        content_a = reg_a.load(CONTENT_MD)
        content_b = reg_b.load(CONTENT_MD)
    except _CONN_ERRORS as exc:
        pytest.skip(f"compiler endpoint unreachable: {exc}")

    # Cross-introduce on the freshly-compiled overlay.
    content_a.network.add_verified_peer(Peer(content_b.my_peer.public_key, address=addr_b))
    content_b.network.add_verified_peer(Peer(content_a.my_peer.public_key, address=addr_a))

    content_a.local_index = [
        {"magnet": "magnet:?xt=urn:btih:111", "name": "Creative Commons Audio Archive 2023.mp3",
         "size": 4200000, "mime": "audio/mpeg", "tags": ["cc", "audio"]},
        {"magnet": "magnet:?xt=urn:btih:222", "name": "lecture-physics.mp4",
         "size": 99000000, "mime": "video/mp4", "tags": ["edu"]},
    ]

    SearchRequestPayload = reg_b._compiled[CONTENT_HASH].payload_classes["SEARCH_REQUEST"]
    content_b.ez_send(
        Peer(content_a.my_peer.public_key, address=addr_a),
        SearchRequestPayload(b"creative"),
    )

    for _ in range(60):
        if content_b.response_cache:
            break
        await asyncio.sleep(0.05)

    names = [r.get("name") for r in content_b.response_cache]
    assert "Creative Commons Audio Archive 2023.mp3" in names
    assert "lecture-physics.mp4" not in names
