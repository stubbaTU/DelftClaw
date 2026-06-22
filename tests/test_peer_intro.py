"""Tests for ``PEER_INTRO`` — live wallet + overlay catalogue exchange.

Two SeedboxCommunities complete a community-join (signed-log) round-trip. On
accept, both sides must populate ``peer_meta`` with the other's wallet_address
and known_overlays within ~1s of the response arriving.

Also covers:
  - Unconfigured wallet_address skips the send silently (no crash).
  - PEER_INTRO from a peer who was rejected is NOT triggered (the auto-send
    sits behind the accepted=True check).
  - Defensive: malformed msgpack in known_overlays is dropped without
    crashing the receiver.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.community import (
    PeerIntroPayload,
    PeerMeta,
    SeedboxCommunity,
)


# Community-join callbacks: (peer, entry) -> (accepted, reason). The decision is
# whatever a community-state replay would return; here we stub accept/reject so
# the test isolates the PEER_INTRO exchange that follows admission.
def _accept(_peer, _entry) -> tuple[bool, str]:
    return True, ""


def _reject(_peer, _entry) -> tuple[bool, str]:
    return False, "rejected_for_test"


# A minimal signed_entry the joiner ships; the stub callback ignores its content.
_DONATION = {"type": "donation_intent", "details": {"amount_sats": 10_000}}


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
async def two_seedboxes(tmp_path):
    """Two IPv8 nodes pre-introduced; gatekeeper (A) admits; joiner (B) donates.

    Yields (sb_alice, sb_bob, peer_alice_for_bob, peer_bob_for_alice).
    """
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

    yield sb_a, sb_b, peer_a_for_b, peer_b_for_a

    await svc_a.stop()
    await svc_b.stop()


# ---------------------------------------------------------------------------
# Happy-path: both sides exchange PEER_INTRO on accept
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_peer_intro_exchanged_after_join_accept(two_seedboxes):
    sb_alice, sb_bob, peer_alice, peer_bob = two_seedboxes

    sb_alice.configure(
        community_join_callback=_accept,
        wallet_address="tb1qalicewalletexample00000000000000000000",
    )
    sb_bob.configure(
        wallet_address="tb1qbobwalletexample0000000000000000000000",
    )
    # Bob has one overlay published locally; Alice has none.
    bob_overlay = b"\xab" * 20
    sb_bob._published[bob_overlay] = "# stub overlay\n"

    join_fut = sb_bob.request_community_join(peer_alice, _DONATION)
    accepted, _reason = await asyncio.wait_for(join_fut, timeout=2.0)
    assert accepted is True

    # Both sides should have stored each other's PeerMeta within ~1s.
    for _ in range(40):
        if peer_bob.mid in sb_alice.peer_meta and peer_alice.mid in sb_bob.peer_meta:
            break
        await asyncio.sleep(0.05)

    alice_view_of_bob = sb_alice.peer_meta.get(peer_bob.mid)
    bob_view_of_alice = sb_bob.peer_meta.get(peer_alice.mid)
    assert alice_view_of_bob is not None, "Alice did not record Bob's intro"
    assert bob_view_of_alice is not None, "Bob did not record Alice's intro"
    assert alice_view_of_bob.wallet_address.startswith("tb1qbob")
    assert bob_view_of_alice.wallet_address.startswith("tb1qalice")
    assert alice_view_of_bob.known_overlays == (bob_overlay,)
    assert bob_view_of_alice.known_overlays == ()


# ---------------------------------------------------------------------------
# Rejected donations do NOT produce PEER_INTRO
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_peer_intro_skipped_on_reject(two_seedboxes):
    sb_alice, sb_bob, peer_alice, peer_bob = two_seedboxes
    sb_alice.configure(
        community_join_callback=_reject,
        wallet_address="tb1qalicewalletexample00000000000000000000",
    )
    sb_bob.configure(wallet_address="tb1qbobwalletexample0000000000000000000000")

    join_fut = sb_bob.request_community_join(peer_alice, _DONATION)
    accepted, _reason = await asyncio.wait_for(join_fut, timeout=2.0)
    assert accepted is False

    await asyncio.sleep(0.3)
    assert peer_bob.mid not in sb_alice.peer_meta
    assert peer_alice.mid not in sb_bob.peer_meta


# ---------------------------------------------------------------------------
# Defensive: missing wallet_address means we just don't send (no crash)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_peer_intro_silent_without_wallet_config(two_seedboxes):
    sb_alice, sb_bob, peer_alice, peer_bob = two_seedboxes
    sb_alice.configure(community_join_callback=_accept)  # no wallet_address
    sb_bob.configure()  # no wallet_address

    join_fut = sb_bob.request_community_join(peer_alice, _DONATION)
    accepted, _reason = await asyncio.wait_for(join_fut, timeout=2.0)
    assert accepted is True

    await asyncio.sleep(0.3)
    # Neither side sent its PEER_INTRO; both _peer_meta should be empty.
    assert sb_alice.peer_meta == {}
    assert sb_bob.peer_meta == {}


# ---------------------------------------------------------------------------
# Defensive: malformed PEER_INTRO does not crash the receiver
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_peer_intro_malformed_msgpack_dropped(two_seedboxes):
    sb_alice, sb_bob, peer_alice, peer_bob = two_seedboxes
    sb_alice.configure(wallet_address="tb1qalicewalletexample00000000000000000000")
    sb_bob.configure(wallet_address="tb1qbobwalletexample0000000000000000000000")

    # Send a deliberately malformed PEER_INTRO from Bob to Alice.
    sb_bob.ez_send(
        Peer(sb_alice.my_peer.public_key, address=sb_alice.endpoint.get_address()),
        PeerIntroPayload(
            wallet_address=b"tb1qbobwalletexample0000000000000000000000",
            known_overlays=b"\xff\xff\xff\xff",  # not valid msgpack
        ),
    )
    await asyncio.sleep(0.3)
    # No entry recorded for Bob — malformed payload was dropped.
    assert peer_bob.mid not in sb_alice.peer_meta


# ---------------------------------------------------------------------------
# Callback fires
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_peer_intro_callback_invoked(two_seedboxes):
    sb_alice, sb_bob, peer_alice, peer_bob = two_seedboxes
    seen: list[tuple[bytes, PeerMeta]] = []
    sb_alice.configure(
        community_join_callback=_accept,
        wallet_address="tb1qalicewalletexample00000000000000000000",
        peer_intro_callback=lambda p, meta: seen.append((p.mid, meta)),
    )
    sb_bob.configure(wallet_address="tb1qbobwalletexample0000000000000000000000")

    join_fut = sb_bob.request_community_join(peer_alice, _DONATION)
    await asyncio.wait_for(join_fut, timeout=2.0)
    for _ in range(40):
        if seen:
            break
        await asyncio.sleep(0.05)
    assert len(seen) == 1
    assert seen[0][0] == peer_bob.mid
    assert seen[0][1].wallet_address.startswith("tb1qbob")
