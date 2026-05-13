"""End-to-end test for the ``network_join`` tool.

A joining agent is given only the manifest markdown + the genesis peer's
endpoint that the manifest itself names; from there, one tool call must
produce a fully-admitted, overlay-loaded state — no recipe-style turns
on the LLM side. This is the zero-shot agency the design is built for.

Bitcoin testnet broadcasts are mocked (the test wallet's ``send`` is
monkey-patched to return a known txid); admission verification is
mocked via ``AlwaysAcceptVerifier`` from test_peer_intro.py.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.peer import Peer

from agent.runtime import AgentConfig, OpenClawAgent
from agent.tools import build_tools
from communication.bittorrent import StubBitTorrentService
from communication.community import overlay_id
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol import StubLLMClient, community_id_from_md
from protocol.examples.content_community_stub import CONTENT_COMMUNITY_SOURCE
from admission.donation_verifier import DonationVerification


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTENT_MD = (REPO_ROOT / "protocol" / "examples" / "content_community.md").read_text()
CONTENT_HASH = overlay_id(CONTENT_MD)


class AlwaysAcceptVerifier:
    def verify(self, txid_hex: str) -> DonationVerification:
        return DonationVerification(accepted=True, paid_sats=10_000, confirmations=1)


def _stub_llm() -> StubLLMClient:
    return StubLLMClient(sources={
        community_id_from_md(CONTENT_MD).hex():
            "```python\n" + CONTENT_COMMUNITY_SOURCE + "```",
    })


def _build_manifest(*, alice_address: str, alice_pubkey_hex: str,
                    alice_host: str, alice_port: int,
                    default_overlay_hash: str) -> str:
    """Build a manifest that names Alice as the only genesis peer + gatekeeper."""
    return (
        "# Identity\n"
        "- name: test_network\n"
        "- version: 1.0.0\n"
        "- description: A test network for network_join.\n"
        "\n"
        "# Admission\n"
        f"- gatekeeper_address: {alice_address}\n"
        "- min_sats: 10000\n"
        "- min_confirmations: 0\n"
        "\n"
        "# Genesis Peers\n"
        "| host | port | pubkey_hex |\n"
        "|------|------|------------|\n"
        f"| {alice_host} | {alice_port} | {alice_pubkey_hex} |\n"
        "\n"
        "# Default Overlays\n"
        f"- sha1: {default_overlay_hash}\n"
    )


@pytest_asyncio.fixture
async def two_agents_with_publishable_overlay(tmp_path):
    """Alice is the genesis seedbox; Bob is the joiner. Alice publishes
    content_community over the wire; Alice's verifier admits any txid."""
    save_a = tmp_path / "a"
    save_b = tmp_path / "b"

    alice = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "army van defense carry jealous true garbage claim echo media make crunch"
        ).load(), network="TESTNET"),
        llm=_stub_llm(),
        config=AgentConfig(port=0, save_dir=save_a),
        bt_service=StubBitTorrentService(save_dir=save_a),
    )
    bob = OpenClawAgent(
        identity=AgentIdentity.from_seed(MnemonicSeedSource(
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about"
        ).load(), network="TESTNET"),
        llm=_stub_llm(),
        config=AgentConfig(port=0, save_dir=save_b),
        bt_service=StubBitTorrentService(save_dir=save_b),
    )
    await alice.start()
    await bob.start()

    # Alice serves the descriptor and runs an accept-everything verifier.
    alice.seedbox.publish_overlay(CONTENT_MD)
    alice.seedbox.configure(verifier=AlwaysAcceptVerifier())

    # Mock Bob's wallet so it never tries to broadcast on testnet.
    sends: list[tuple[str, int]] = []

    def fake_send(to: str, sats: int) -> str:
        sends.append((to, sats))
        return "aa" * 32   # 64-char hex txid

    bob.wallet.send = fake_send  # type: ignore[method-assign]

    yield alice, bob, sends

    await alice.stop()
    await bob.stop()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_join_end_to_end(two_agents_with_publishable_overlay):
    alice, bob, sends = two_agents_with_publishable_overlay

    manifest_md = _build_manifest(
        alice_address=alice.wallet.address(),
        alice_pubkey_hex=alice.pubkey_hex,
        alice_host="127.0.0.1",
        alice_port=alice.address[1],
        default_overlay_hash=CONTENT_HASH.hex(),
    )

    b_tools = build_tools(bob)
    result = await b_tools.dispatch("network_join", {"manifest_md_text": manifest_md})

    assert "error" not in result, f"unexpected error: {result}"
    assert result["accepted"] is True
    assert CONTENT_HASH.hex() in result["overlays_loaded"]
    assert result["overlay_errors"] == []
    assert result["txid"] == "aa" * 32

    # Bob donated to Alice's actual address for min_sats.
    assert sends == [(alice.wallet.address(), 10000)]

    # Bob's local state reflects the manifest.
    assert bob.network_manifest is not None
    assert bob.network_manifest.identity["name"] == "test_network"

    # Bob speaks content_community now.
    assert bob.registry.get(CONTENT_HASH) is not None


# ---------------------------------------------------------------------------
# Sad paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_join_bad_manifest_returns_error(two_agents_with_publishable_overlay):
    _alice, bob, _ = two_agents_with_publishable_overlay
    b_tools = build_tools(bob)
    result = await b_tools.dispatch(
        "network_join",
        {"manifest_md_text": "# Identity\nbroken"},
    )
    assert "error" in result
    assert "manifest_parse_failed" in result["error"]
    # Wallet must NOT have been touched.
    assert bob.network_manifest is None


@pytest.mark.asyncio
async def test_network_join_no_genesis_peers_reachable(two_agents_with_publishable_overlay):
    """If the manifest's only peer doesn't actually exist, the tool fails before donating."""
    _alice, bob, sends = two_agents_with_publishable_overlay

    # Manifest names a real-looking but unrelated pubkey/port.
    manifest_md = _build_manifest(
        alice_address="tb1qexamplexxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        alice_pubkey_hex="dd" * 37,   # 74 hex chars, but not a real pubkey
        alice_host="127.0.0.1",
        alice_port=1024,
        default_overlay_hash=CONTENT_HASH.hex(),
    )
    b_tools = build_tools(bob)
    result = await b_tools.dispatch("network_join", {"manifest_md_text": manifest_md})

    # No genesis peers means we cannot route the admission round-trip.
    assert "error" in result
    assert result["error"] == "no_genesis_peers_reachable"
    # And critically — no wallet send happened.
    assert sends == []


# ---------------------------------------------------------------------------
# agent_inject_manifest + cached-manifest network_join
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_agent_inject_manifest_caches_for_later(two_agents_with_publishable_overlay):
    alice, bob, _ = two_agents_with_publishable_overlay
    manifest_md = _build_manifest(
        alice_address=alice.wallet.address(),
        alice_pubkey_hex=alice.pubkey_hex,
        alice_host="127.0.0.1",
        alice_port=alice.address[1],
        default_overlay_hash=CONTENT_HASH.hex(),
    )

    b_tools = build_tools(bob)
    inject = await b_tools.dispatch(
        "agent_inject_manifest",
        {"md_text": manifest_md},
    )
    assert "error" not in inject
    assert inject["name"] == "test_network"
    assert inject["genesis_peers"] == 1
    assert bob.network_manifest is not None


@pytest.mark.asyncio
async def test_agent_inject_manifest_bad_returns_error(two_agents_with_publishable_overlay):
    _alice, bob, _ = two_agents_with_publishable_overlay
    b_tools = build_tools(bob)
    result = await b_tools.dispatch(
        "agent_inject_manifest",
        {"md_text": "# Identity\nbroken"},
    )
    assert "error" in result
    assert "manifest_parse_failed" in result["error"]
    assert bob.network_manifest is None


@pytest.mark.asyncio
async def test_network_join_uses_cached_manifest_when_no_arg(
    two_agents_with_publishable_overlay,
):
    """Inject manifest first, then call network_join() with NO args."""
    alice, bob, sends = two_agents_with_publishable_overlay
    manifest_md = _build_manifest(
        alice_address=alice.wallet.address(),
        alice_pubkey_hex=alice.pubkey_hex,
        alice_host="127.0.0.1",
        alice_port=alice.address[1],
        default_overlay_hash=CONTENT_HASH.hex(),
    )

    b_tools = build_tools(bob)
    await b_tools.dispatch("agent_inject_manifest", {"md_text": manifest_md})

    result = await b_tools.dispatch("network_join", {})
    assert "error" not in result, f"unexpected error: {result}"
    assert result["accepted"] is True
    assert CONTENT_HASH.hex() in result["overlays_loaded"]
    assert sends == [(alice.wallet.address(), 10000)]


@pytest.mark.asyncio
async def test_network_join_with_no_args_and_no_cached_manifest_errors(
    two_agents_with_publishable_overlay,
):
    _alice, bob, sends = two_agents_with_publishable_overlay
    b_tools = build_tools(bob)
    result = await b_tools.dispatch("network_join", {})
    assert "error" in result
    assert result["error"] == "no_manifest_loaded"
    assert sends == []


# ---------------------------------------------------------------------------
# --genesis publishing path (the genesis agent serves the manifest)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_genesis_publishes_manifest_into_seedbox(two_agents_with_publishable_overlay):
    """Verify the wire surface a real ``--genesis`` flag exercises: the
    manifest hash is in published_manifests, so a peer requesting it
    via MANIFEST_REQUEST would get a delivery."""
    alice, _bob, _ = two_agents_with_publishable_overlay
    manifest_md = _build_manifest(
        alice_address=alice.wallet.address(),
        alice_pubkey_hex=alice.pubkey_hex,
        alice_host="127.0.0.1",
        alice_port=alice.address[1],
        default_overlay_hash=CONTENT_HASH.hex(),
    )

    # Simulate what `python -m agent ... --genesis manifest.md` does:
    alice.load_manifest(manifest_md)
    md_hash = alice.seedbox.publish_manifest(manifest_md)

    assert md_hash in alice.seedbox.published_manifests
    assert alice.seedbox.published_manifests[md_hash] == manifest_md
    assert alice.network_manifest is not None
    assert alice.network_manifest.identity["name"] == "test_network"
