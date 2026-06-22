"""Tests for ``OpenClawAgent.ensure_default_overlays_loaded``.

Drives the wire-distribution path end-to-end in process: alice publishes
the content_community descriptor via the bootstrap community, bob loads
a manifest that names alice as a genesis peer and the descriptor's
``community_id`` as a default overlay, then calls
``ensure_default_overlays_loaded`` which:

1. Sees ``content_community`` in ``manifest.default_overlays``.
2. Picks alice (the only genesis peer) as the source.
3. Sends ``OVERLAY_REQUEST`` over the bootstrap community.
4. Awaits ``OVERLAY_DELIVERY``.
5. Compiles + registers the descriptor in bob's registry.

Mirrors the manual ``test_mcp_client_can_publish_fetch_and_invoke_overlay``
test pattern but skips the MCP layer (this is a runtime-level test).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio

from agent import AgentConfig, OpenClawAgent
from communication.bittorrent import StubBitTorrentService
from communication.community import overlay_id
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol import community_id_from_md
from _live_llm import live_compiler_llm, requires_live_llm


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTENT_MD = (REPO_ROOT / "protocol" / "examples" / "content_community.md").read_text()
CONTENT_HASH = overlay_id(CONTENT_MD)

# Wire-distribution of default overlays compiles content_community via a real
# LLM on both sides, so the module skips without an endpoint (stubs removed).
pytestmark = requires_live_llm


@pytest_asyncio.fixture
async def alice_and_bob(tmp_path):
    """Two agents started side by side; alice has published the content overlay."""
    save_a = tmp_path / "a"
    save_b = tmp_path / "b"

    alice = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "army van defense carry jealous true garbage claim echo media make crunch"
        ).load(), network="TESTNET"),
        llm=live_compiler_llm(),
        config=AgentConfig(port=0, save_dir=save_a),
        bt_service=StubBitTorrentService(save_dir=save_a),
    )
    bob = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).load(), network="TESTNET"),
        llm=live_compiler_llm(),
        config=AgentConfig(port=0, save_dir=save_b),
        bt_service=StubBitTorrentService(save_dir=save_b),
    )

    await alice.start()
    await bob.start()

    # Alice publishes the overlay so her bootstrap community holds the .md.
    alice.publish_overlay(CONTENT_MD)

    # Cross-introduce on the bootstrap community so OVERLAY_REQUEST routing works.
    from ipv8.peer import Peer
    alice.seedbox.network.add_verified_peer(
        Peer(bob.seedbox.my_peer.public_key, address=bob.address)
    )
    bob.seedbox.network.add_verified_peer(
        Peer(alice.seedbox.my_peer.public_key, address=alice.address)
    )

    yield alice, bob

    await alice.stop()
    await bob.stop()


def _manifest_md_with_alice_as_genesis(
    alice: OpenClawAgent,
    *,
    include_default_overlay: bool,
) -> str:
    """Construct a minimal manifest that names alice as genesis."""
    overlays_section = (
        f"- sha1: {CONTENT_HASH.hex()}  (default overlay)"
        if include_default_overlay
        else "(none)"
    )
    host, port = alice.address
    pubkey_hex = alice.pubkey_hex
    return (
        "# Identity\n"
        "- name: ensure_default_overlays_test\n"
        "- version: 1.0.0\n"
        "- description: Manifest for ensure_default_overlays_loaded round-trip test.\n"
        "\n"
        "# Admission\n"
        f"- gatekeeper_address: {alice.wallet.address()}\n"
        "- min_sats: 10000\n"
        "- min_confirmations: 0\n"
        "- bootstrap_cap_sats: 100000\n"
        "\n"
        "# Genesis Peers\n"
        "| host | port | pubkey_hex |\n"
        "|------|------|------------|\n"
        f"| {host} | {port} | {pubkey_hex} |\n"
        "\n"
        "# Default Overlays\n"
        f"{overlays_section}\n"
    )


@pytest.mark.asyncio
async def test_ensure_default_overlays_loaded_fetches_missing_overlay(
    alice_and_bob,
):
    """Bob has no manifest loaded → registry empty → after load+ensure,
    the content overlay has been fetched from alice and registered."""
    alice, bob = alice_and_bob

    # Bob does not yet hold the content overlay.
    assert bob.registry.get(CONTENT_HASH) is None

    # Bob loads a manifest naming alice as genesis and content_community as
    # a default overlay. load_manifest pre-introduces alice into bob's
    # bootstrap community peer set.
    md = _manifest_md_with_alice_as_genesis(alice, include_default_overlay=True)
    bob.load_manifest(md)

    # Now exercise the helper.
    loaded, errors = await bob.ensure_default_overlays_loaded()

    assert errors == []
    assert loaded == [CONTENT_HASH.hex()]
    # The descriptor compiled + registered into bob's registry.
    assert bob.registry.get(CONTENT_HASH) is not None


@pytest.mark.asyncio
async def test_ensure_default_overlays_loaded_noop_when_already_loaded(
    alice_and_bob,
):
    """If bob already holds the overlay locally, the helper short-circuits
    without sending OVERLAY_REQUEST and reports the cid as already loaded."""
    alice, bob = alice_and_bob

    # Pre-load on bob too.
    bob.publish_overlay(CONTENT_MD)
    assert bob.registry.get(CONTENT_HASH) is not None

    md = _manifest_md_with_alice_as_genesis(alice, include_default_overlay=True)
    bob.load_manifest(md)

    loaded, errors = await bob.ensure_default_overlays_loaded()

    assert errors == []
    assert loaded == [CONTENT_HASH.hex()]


@pytest.mark.asyncio
async def test_ensure_default_overlays_loaded_empty_when_no_defaults(
    alice_and_bob,
):
    """A manifest with no default_overlays produces an empty result."""
    alice, bob = alice_and_bob

    md = _manifest_md_with_alice_as_genesis(alice, include_default_overlay=False)
    bob.load_manifest(md)

    loaded, errors = await bob.ensure_default_overlays_loaded()

    assert loaded == []
    assert errors == []


@pytest.mark.asyncio
async def test_ensure_default_overlays_loaded_noop_when_no_manifest(
    alice_and_bob,
):
    """No manifest loaded → no work, no errors."""
    _alice, bob = alice_and_bob
    loaded, errors = await bob.ensure_default_overlays_loaded()
    assert loaded == []
    assert errors == []
