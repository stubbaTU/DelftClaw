from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from admission.donation_verifier import DonationVerification
from communication.community import (
    CommunityJoinRequestPayload,
    CommunityJoinResponsePayload,
    CommunityLineageConfig,
    JoinRequestPayload,
    JoinResponsePayload,
    LineageChallengePayload,
    LineageProofPayload,
    ManifestDeliveryPayload,
    ManifestOfferPayload,
    ManifestRequestPayload,
    OverlayDeliveryPayload,
    OverlayOfferPayload,
    OverlayRequestPayload,
    PeerIntroPayload,
    SeedboxCommunity,
    _peer_operational_pubkey_hexes,
    lineage_proof_signing_payload,
)
from identity.lineage.canonical import canonical_hash, certificate_hash
from identity.lineage.certificates import issue_child_certificate, utc_now_iso
from identity.lineage.merkle import merkle_proof, merkle_root
from identity.lineage.mock_anchor import MockAnchorBackend
from identity.lineage.models import CertificateBatch, LineageProof


class AlwaysAcceptVerifier:
    def verify(self, txid_hex: str) -> DonationVerification:
        return DonationVerification(accepted=True, paid_sats=10_000, confirmations=1)


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

    peer_b_for_a = Peer(sb_b.my_peer.public_key, address=sb_b.endpoint.get_address())
    peer_a_for_b = Peer(sb_a.my_peer.public_key, address=sb_a.endpoint.get_address())
    sb_a.network.add_verified_peer(peer_b_for_a)
    sb_b.network.add_verified_peer(peer_a_for_b)

    yield sb_a, sb_b, peer_a_for_b, peer_b_for_a

    await svc_a.stop()
    await svc_b.stop()


def _pubkey_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _iso(offset_seconds: int = 0) -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        + timedelta(seconds=offset_seconds)
    ).isoformat().replace("+00:00", "Z")


def _proof_for_peer(peer: Peer) -> tuple[dict, tuple[dict[str, str], ...]]:
    root_key = Ed25519PrivateKey.generate()
    child_key = Ed25519PrivateKey.generate()
    operational_pubkey = sorted(_peer_operational_pubkey_hexes(peer), key=len)[0]
    certificate = issue_child_certificate(
        parent_signing_key=root_key,
        family_id="lineage-handshake-family",
        parent_agent_id="root-agent",
        parent_authority_pubkey=_pubkey_hex(root_key),
        child_agent_id=peer.mid.hex(),
        child_authority_pubkey=_pubkey_hex(child_key),
        child_operational_pubkey=operational_pubkey,
        issued_at=_iso(-60),
        expires_at=_iso(3600),
        capabilities=["chat"],
        anchor_policy={"required": True, "min_confirmations": 0},
    )
    leaves = [certificate_hash(certificate)]
    root = merkle_root(leaves)
    batch = CertificateBatch(
        batch_id=canonical_hash({
            "certificate_id": certificate.certificate_id,
            "created_at": utc_now_iso(),
            "kind": "lineage_certificate_batch_v1",
        }),
        merkle_root=root,
        leaf_hashes=leaves,
        certificate_ids=[certificate.certificate_id],
        created_at=utc_now_iso(),
    )
    anchor = MockAnchorBackend(confirmations=1).create_anchor(batch)
    proof = LineageProof(
        leaf_certificate=certificate,
        chain=[],
        merkle_leaf_hash=leaves[0],
        merkle_proof=merkle_proof(leaves, 0),
        merkle_root=root,
        anchor_id=anchor.anchor_id,
        anchor_record=anchor,
    )
    trusted_roots = ({
        "agent_id": "root-agent",
        "authority_pubkey": _pubkey_hex(root_key),
    },)
    return proof.to_dict(), trusted_roots


async def _wait_for_status(sb: SeedboxCommunity, peer_mid: bytes) -> dict:
    for _ in range(80):
        status = sb.lineage_peer_status.get(peer_mid)
        if status is not None:
            return status
        await asyncio.sleep(0.025)
    raise AssertionError("lineage status was not recorded")


@pytest.mark.asyncio
async def test_lineage_disabled_accepts_old_peers(two_seedboxes):
    sb_a, sb_b, peer_a, _peer_b = two_seedboxes
    sb_a.configure(verifier=AlwaysAcceptVerifier())

    accepted = await asyncio.wait_for(
        sb_b.request_join(peer_a, donation_txid=b"\x01"),
        timeout=2.0,
    )

    assert accepted is True
    assert sb_a.lineage_peer_status == {}


@pytest.mark.asyncio
async def test_lineage_optional_accepts_and_records_valid_status(two_seedboxes):
    sb_a, sb_b, peer_a, peer_b = two_seedboxes
    proof, trusted_roots = _proof_for_peer(peer_b)
    sb_a.configure(
        verifier=AlwaysAcceptVerifier(),
        lineage_config=CommunityLineageConfig(
            enabled=True,
            required=False,
            trusted_roots=trusted_roots,
            accepted_capabilities=("chat",),
        ),
    )
    sb_b.configure(lineage_proof_provider=lambda: proof)

    accepted = await asyncio.wait_for(
        sb_b.request_join(peer_a, donation_txid=b"\x02"),
        timeout=2.0,
    )
    status = await _wait_for_status(sb_a, peer_b.mid)

    assert accepted is True
    assert status["ok"] is True
    assert status["status"] == "valid"


@pytest.mark.asyncio
async def test_lineage_optional_accepts_and_records_invalid_status(two_seedboxes):
    sb_a, sb_b, peer_a, peer_b = two_seedboxes
    proof, trusted_roots = _proof_for_peer(peer_b)
    proof["leaf_certificate"]["child_operational_pubkey"] = "00" * 32
    sb_a.configure(
        verifier=AlwaysAcceptVerifier(),
        lineage_config=CommunityLineageConfig(
            enabled=True,
            required=False,
            trusted_roots=trusted_roots,
        ),
    )
    sb_b.configure(lineage_proof_provider=lambda: proof)

    accepted = await asyncio.wait_for(
        sb_b.request_join(peer_a, donation_txid=b"\x03"),
        timeout=2.0,
    )
    status = await _wait_for_status(sb_a, peer_b.mid)

    assert accepted is True
    assert status["ok"] is False
    assert status["status"] == "invalid"


@pytest.mark.asyncio
async def test_lineage_required_accepts_valid_proof(two_seedboxes):
    sb_a, sb_b, peer_a, peer_b = two_seedboxes
    proof, trusted_roots = _proof_for_peer(peer_b)
    sb_a.configure(
        verifier=AlwaysAcceptVerifier(),
        lineage_config=CommunityLineageConfig(
            enabled=True,
            required=True,
            trusted_roots=trusted_roots,
            accepted_capabilities=("chat",),
        ),
    )
    sb_b.configure(lineage_proof_provider=lambda: proof)

    accepted = await asyncio.wait_for(
        sb_b.request_join(peer_a, donation_txid=b"\x04"),
        timeout=2.0,
    )

    assert accepted is True
    assert sb_a.lineage_peer_status[peer_b.mid]["ok"] is True


@pytest.mark.asyncio
async def test_lineage_required_rejects_missing_proof(two_seedboxes):
    sb_a, sb_b, peer_a, peer_b = two_seedboxes
    _proof, trusted_roots = _proof_for_peer(peer_b)
    sb_a.configure(
        verifier=AlwaysAcceptVerifier(),
        lineage_config=CommunityLineageConfig(
            enabled=True,
            required=True,
            trusted_roots=trusted_roots,
            challenge_timeout_s=0.5,
        ),
    )

    accepted = await asyncio.wait_for(
        sb_b.request_join(peer_a, donation_txid=b"\x05"),
        timeout=2.0,
    )

    assert accepted is False
    assert sb_a.lineage_peer_status[peer_b.mid]["status"] == "missing"


@pytest.mark.asyncio
async def test_lineage_required_rejects_invalid_proof(two_seedboxes):
    sb_a, sb_b, peer_a, peer_b = two_seedboxes
    proof, trusted_roots = _proof_for_peer(peer_b)
    proof["leaf_certificate"]["child_operational_pubkey"] = "00" * 32
    sb_a.configure(
        verifier=AlwaysAcceptVerifier(),
        lineage_config=CommunityLineageConfig(
            enabled=True,
            required=True,
            trusted_roots=trusted_roots,
        ),
    )
    sb_b.configure(lineage_proof_provider=lambda: proof)

    accepted = await asyncio.wait_for(
        sb_b.request_join(peer_a, donation_txid=b"\x06"),
        timeout=2.0,
    )

    assert accepted is False
    assert sb_a.lineage_peer_status[peer_b.mid]["status"] == "invalid"


@pytest.mark.asyncio
async def test_lineage_replayed_nonce_is_rejected(two_seedboxes):
    sb_a, sb_b, _peer_a, peer_b = two_seedboxes
    proof, trusted_roots = _proof_for_peer(peer_b)
    sb_a.configure(
        lineage_config=CommunityLineageConfig(
            enabled=True,
            required=True,
            trusted_roots=trusted_roots,
        ),
    )
    proof_json = json.dumps(proof, sort_keys=True, separators=(",", ":")).encode("utf-8")
    nonce = b"r" * 32
    signature = sb_b._sign_lineage_payload(lineage_proof_signing_payload(nonce, proof_json))

    SeedboxCommunity.on_lineage_proof.__wrapped__(
        sb_a,
        peer_b,
        LineageProofPayload(nonce, proof_json, signature),
    )

    assert sb_a.lineage_peer_status[peer_b.mid]["status"] == "replay"


def test_lineage_message_ids_do_not_collide_with_existing_ids():
    existing_ids = {
        JoinRequestPayload.msg_id,
        JoinResponsePayload.msg_id,
        OverlayOfferPayload.msg_id,
        OverlayRequestPayload.msg_id,
        OverlayDeliveryPayload.msg_id,
        ManifestOfferPayload.msg_id,
        ManifestRequestPayload.msg_id,
        ManifestDeliveryPayload.msg_id,
        PeerIntroPayload.msg_id,
        CommunityJoinRequestPayload.msg_id,
        CommunityJoinResponsePayload.msg_id,
    }

    assert existing_ids == set(range(1, 12))
    assert LineageChallengePayload.msg_id not in existing_ids
    assert LineageProofPayload.msg_id not in existing_ids
    assert LineageChallengePayload.msg_id == 12
    assert LineageProofPayload.msg_id == 13
