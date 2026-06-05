from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.lineage.canonical import canonical_hash, certificate_body_hash, certificate_hash
from identity.lineage.cache import VerificationResultCache
from identity.lineage.certificates import (
    certificate_allows_capability,
    issue_child_certificate,
    verify_certificate_id,
    verify_certificate_signature,
)
from identity.lineage.merkle import merkle_proof, merkle_root, verify_merkle_proof
from identity.lineage.mock_anchor import MockAnchorBackend
from identity.lineage.models import CertificateBatch, LineageProof, RevocationEventV1, VerificationResult
from identity.lineage.revocation import (
    issue_revocation_event,
    replay_revocation_feed,
    verify_revocation_event_id,
    verify_revocation_event_signature,
)
from identity.lineage.verifier import verify_lineage_proof


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


def _certificate(
    *,
    expires_in: int = 3600,
    capabilities: list[str] | None = None,
):
    parent_key = Ed25519PrivateKey.generate()
    child_key = Ed25519PrivateKey.generate()
    certificate = issue_child_certificate(
        parent_signing_key=parent_key,
        family_id="family-alpha",
        parent_agent_id="root-agent",
        parent_authority_pubkey=_pubkey_hex(parent_key),
        child_agent_id="child-agent",
        child_authority_pubkey=_pubkey_hex(child_key),
        child_operational_pubkey="operational-pubkey",
        issued_at=_iso(-60),
        expires_at=_iso(expires_in),
        capabilities=capabilities or ["chat", "tool.use"],
        constraints={"max_depth": 1},
        anchor_policy={"required": True, "min_confirmations": 0},
    )
    return parent_key, child_key, certificate


def _proof():
    return _proof_for_certificate(_certificate())


def _proof_for_certificate(certificate_bundle):
    parent_key, _child_key, certificate = certificate_bundle
    leaves = [
        canonical_hash({"noise": "left"}),
        certificate_hash(certificate),
        canonical_hash({"noise": "right"}),
    ]
    root = merkle_root(leaves)
    batch = CertificateBatch(
        batch_id="batch-1",
        merkle_root=root,
        leaf_hashes=leaves,
        certificate_ids=["noise-left", certificate.certificate_id, "noise-right"],
        created_at=_iso(),
    )
    backend = MockAnchorBackend(confirmations=3)
    anchor = backend.create_anchor(batch)
    proof = LineageProof(
        leaf_certificate=certificate,
        chain=[],
        merkle_leaf_hash=leaves[1],
        merkle_proof=merkle_proof(leaves, 1),
        merkle_root=root,
        anchor_id=anchor.anchor_id,
        anchor_record=anchor,
    )
    trusted_roots = [{"agent_id": "root-agent", "authority_pubkey": _pubkey_hex(parent_key)}]
    return proof, backend, trusted_roots


class _CountingAnchorBackend:
    def __init__(
        self,
        *,
        ok: bool = True,
        status: str = "valid",
        errors: list[str] | None = None,
    ) -> None:
        self.ok = ok
        self.status = status
        self.errors = errors or []
        self.calls = 0

    def verify_anchor(self, anchor_record, merkle_root: str, min_confirmations: int) -> VerificationResult:
        self.calls += 1
        return VerificationResult(
            ok=self.ok,
            status=self.status,
            anchor_id=anchor_record.anchor_id,
            confirmations=anchor_record.confirmations,
            errors=list(self.errors),
        )


def test_canonical_certificate_hashing_is_stable() -> None:
    _parent_key, _child_key, certificate = _certificate()
    data = certificate.to_dict()
    shuffled = {key: data[key] for key in reversed(list(data.keys()))}

    assert certificate_hash(data) == certificate_hash(shuffled)
    assert certificate_body_hash(data) == certificate.certificate_id


def test_parent_signed_child_certificate_creation_and_verification() -> None:
    _parent_key, _child_key, certificate = _certificate()

    assert verify_certificate_id(certificate) is True
    assert verify_certificate_signature(certificate) is True


def test_tamper_rejection() -> None:
    _parent_key, _child_key, certificate = _certificate()
    tampered = replace(certificate, child_agent_id="mallory")

    assert verify_certificate_id(tampered) is False
    assert verify_certificate_signature(tampered) is False


def test_expiry_checks_reject_expired_lineage_proof() -> None:
    proof, backend, trusted_roots = _proof_for_certificate(_certificate(expires_in=-1))

    result = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=backend,
    )

    assert result.ok is False
    assert result.status == "expired"


def test_capability_checks() -> None:
    _parent_key, _child_key, certificate = _certificate(capabilities=["chat"])

    assert certificate_allows_capability(certificate, "chat") is True
    assert certificate_allows_capability(certificate, "tool.use") is False


def test_lineage_verifier_rejects_missing_requested_capability() -> None:
    proof, backend, trusted_roots = _proof()

    result = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="admin",
        anchor_backend=backend,
    )

    assert result.ok is False
    assert result.status == "invalid"
    assert "requested capability" in result.errors[0]


def test_merkle_root_proof_creation_and_verification() -> None:
    leaves = [
        canonical_hash({"leaf": 1}),
        canonical_hash({"leaf": 2}),
        canonical_hash({"leaf": 3}),
    ]
    root = merkle_root(leaves)
    proof = merkle_proof(leaves, 2)

    assert verify_merkle_proof(leaf_hash=leaves[2], proof=proof, expected_root=root) is True
    assert verify_merkle_proof(leaf_hash=canonical_hash({"leaf": "wrong"}), proof=proof, expected_root=root) is False


def test_mock_anchor_verification() -> None:
    leaves = [canonical_hash({"leaf": 1}), canonical_hash({"leaf": 2})]
    batch = CertificateBatch(
        batch_id="batch-anchor",
        merkle_root=merkle_root(leaves),
        leaf_hashes=leaves,
        certificate_ids=["one", "two"],
        created_at=_iso(),
    )
    backend = MockAnchorBackend(confirmations=2)
    anchor = backend.create_anchor(batch)

    valid = backend.verify_anchor(anchor, batch.merkle_root, min_confirmations=2)
    mismatch = backend.verify_anchor(anchor, canonical_hash({"wrong": "root"}), min_confirmations=2)
    insufficient = backend.verify_anchor(anchor, batch.merkle_root, min_confirmations=3)

    assert valid.ok is True
    assert mismatch.ok is False
    assert mismatch.status == "unanchored"
    assert insufficient.ok is False
    assert insufficient.status == "insufficient_confirmations"


def test_high_level_lineage_proof_verification() -> None:
    proof, backend, trusted_roots = _proof()

    result = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="tool.use",
        anchor_backend=backend,
    )

    assert result.ok is True
    assert result.status == "valid"
    assert result.subject_agent_id == "child-agent"
    assert result.trusted_root_agent_id == "root-agent"
    assert result.certificate_id == proof.leaf_certificate.certificate_id


def test_lineage_verification_cache_hits_for_identical_proof_policy_and_feed_version(tmp_path) -> None:
    proof, _backend, trusted_roots = _proof()
    cache = VerificationResultCache(tmp_path / "cache.json")
    first_backend = _CountingAnchorBackend()
    second_backend = _CountingAnchorBackend(ok=False, status="unanchored", errors=["cache was not used"])

    first = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=first_backend,
        cache=cache,
    )
    second = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=second_backend,
        cache=cache,
    )

    assert first.ok is True
    assert second.ok is True
    assert first_backend.calls == 1
    assert second_backend.calls == 0


def test_lineage_verification_cache_misses_when_requested_capability_changes(tmp_path) -> None:
    proof, _backend, trusted_roots = _proof()
    cache = VerificationResultCache(tmp_path / "cache.json")
    first_backend = _CountingAnchorBackend()
    second_backend = _CountingAnchorBackend(ok=False, status="unanchored", errors=["capability policy changed"])

    assert verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=first_backend,
        cache=cache,
    ).ok is True
    second = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="tool.use",
        anchor_backend=second_backend,
        cache=cache,
    )

    assert second.ok is False
    assert second.status == "unanchored"
    assert second_backend.calls == 1


def test_lineage_verification_cache_misses_when_min_confirmations_changes(tmp_path) -> None:
    proof, _backend, trusted_roots = _proof()
    cache = VerificationResultCache(tmp_path / "cache.json")
    first_backend = _CountingAnchorBackend()
    second_backend = _CountingAnchorBackend(ok=False, status="insufficient_confirmations", errors=["policy changed"])

    assert verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=first_backend,
        min_confirmations=0,
        cache=cache,
    ).ok is True
    second = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=second_backend,
        min_confirmations=1,
        cache=cache,
    )

    assert second.ok is False
    assert second.status == "insufficient_confirmations"
    assert second_backend.calls == 1


def test_lineage_verification_cache_misses_on_anchor_mismatch(tmp_path) -> None:
    proof, _backend, trusted_roots = _proof()
    cache = VerificationResultCache(tmp_path / "cache.json")
    first_backend = _CountingAnchorBackend()
    second_backend = _CountingAnchorBackend()
    mismatched_anchor = replace(proof, anchor_id="different-anchor")

    assert verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=first_backend,
        cache=cache,
    ).ok is True
    second = verify_lineage_proof(
        mismatched_anchor,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=second_backend,
        cache=cache,
    )

    assert second.ok is False
    assert second.status == "unanchored"
    assert second_backend.calls == 1


def test_lineage_verification_cache_misses_on_merkle_root_mismatch(tmp_path) -> None:
    proof, _backend, trusted_roots = _proof()
    cache = VerificationResultCache(tmp_path / "cache.json")
    first_backend = _CountingAnchorBackend()
    second_backend = _CountingAnchorBackend(ok=False, status="unanchored", errors=["should not verify anchor"])
    mismatched_root = replace(proof, merkle_root=canonical_hash({"different": "root"}))

    assert verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=first_backend,
        cache=cache,
    ).ok is True
    second = verify_lineage_proof(
        mismatched_root,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=second_backend,
        cache=cache,
    )

    assert second.ok is False
    assert second.status == "invalid"
    assert "Merkle proof does not verify" in second.errors
    assert second_backend.calls == 0


def test_lineage_verification_cache_invalidates_when_revocation_feed_version_changes(tmp_path) -> None:
    certificate_bundle = _certificate()
    parent_key, _child_key, certificate = certificate_bundle
    proof, _backend, trusted_roots = _proof_for_certificate(certificate_bundle)
    cache = VerificationResultCache(tmp_path / "cache.json")
    first_backend = _CountingAnchorBackend()
    second_backend = _CountingAnchorBackend(ok=False, status="unanchored", errors=["should not verify anchor"])
    event = issue_revocation_event(
        revoker_signing_key=parent_key,
        certificate_id=certificate.certificate_id,
        family_id=certificate.family_id,
        revoked_by_agent_id=certificate.parent_agent_id,
        revoked_by_pubkey=certificate.parent_authority_pubkey,
        reason="test",
        created_at=_iso(),
    )
    revoked_proof = replace(proof, revocation_events=[event])

    assert verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=first_backend,
        cache=cache,
    ).ok is True
    second = verify_lineage_proof(
        revoked_proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=second_backend,
        cache=cache,
    )

    assert second.ok is False
    assert second.status == "revoked"
    assert second_backend.calls == 0


def test_lineage_verification_cache_preserves_cached_invalid_result(tmp_path) -> None:
    proof, _backend, trusted_roots = _proof()
    cache_path = tmp_path / "cache.json"
    first_backend = _CountingAnchorBackend(ok=False, status="unanchored", errors=["anchor unavailable"])
    second_backend = _CountingAnchorBackend()

    first = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=first_backend,
        cache=cache_path,
    )
    second = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=second_backend,
        cache=cache_path,
    )

    assert first.ok is False
    assert first.status == "unanchored"
    assert second.ok is False
    assert second.status == "unanchored"
    assert second_backend.calls == 0


def test_lineage_verifier_without_cache_reverifies_as_before() -> None:
    proof, _backend, trusted_roots = _proof()
    first_backend = _CountingAnchorBackend()
    second_backend = _CountingAnchorBackend(ok=False, status="unanchored", errors=["no cache"])

    first = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=first_backend,
    )
    second = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=second_backend,
    )

    assert first.ok is True
    assert second.ok is False
    assert second.status == "unanchored"
    assert first_backend.calls == 1
    assert second_backend.calls == 1


def test_signed_revocation_event_creation_and_replay() -> None:
    parent_key, _child_key, certificate = _certificate()
    event = issue_revocation_event(
        revoker_signing_key=parent_key,
        certificate_id=certificate.certificate_id,
        family_id=certificate.family_id,
        revoked_by_agent_id=certificate.parent_agent_id,
        revoked_by_pubkey=certificate.parent_authority_pubkey,
        reason="issuer revoked child",
        created_at=_iso(),
    )
    trusted_roots = [{"agent_id": "root-agent", "authority_pubkey": _pubkey_hex(parent_key)}]

    replay = replay_revocation_feed([event], [certificate], trusted_roots=trusted_roots)

    assert verify_revocation_event_id(event) is True
    assert verify_revocation_event_signature(event) is True
    assert replay.errors == []
    assert replay.revoked_certificate_ids == {certificate.certificate_id}
    assert replay.accepted_event_ids == [event.event_id]


def test_high_level_lineage_proof_rejects_signed_revoked_certificate() -> None:
    certificate_bundle = _certificate()
    parent_key, _child_key, certificate = certificate_bundle
    proof, backend, trusted_roots = _proof_for_certificate(certificate_bundle)
    event = issue_revocation_event(
        revoker_signing_key=parent_key,
        certificate_id=certificate.certificate_id,
        family_id=certificate.family_id,
        revoked_by_agent_id=certificate.parent_agent_id,
        revoked_by_pubkey=certificate.parent_authority_pubkey,
        reason="test",
        created_at=_iso(),
    )
    proof = replace(
        proof,
        revocation_events=[event],
    )

    result = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=backend,
    )

    assert result.ok is False
    assert result.status == "revoked"


def test_high_level_lineage_proof_rejects_unauthorized_revocation_signer() -> None:
    certificate_bundle = _certificate()
    _parent_key, _child_key, certificate = certificate_bundle
    proof, backend, trusted_roots = _proof_for_certificate(certificate_bundle)
    attacker_key = Ed25519PrivateKey.generate()
    event = issue_revocation_event(
        revoker_signing_key=attacker_key,
        certificate_id=certificate.certificate_id,
        family_id=certificate.family_id,
        revoked_by_agent_id="mallory",
        revoked_by_pubkey=_pubkey_hex(attacker_key),
        reason="not authorized",
        created_at=_iso(),
    )
    proof = replace(proof, revocation_events=[event])

    result = verify_lineage_proof(
        proof,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=backend,
    )

    assert result.ok is False
    assert result.status == "invalid"
    assert "revocation signer is not authorized" in result.errors[0]


def test_lineage_proof_from_dict_preserves_legacy_unsigned_revocation_dict() -> None:
    proof, backend, trusted_roots = _proof()
    data = proof.to_dict()
    data["revocation_events"] = [
        {"certificate_id": proof.leaf_certificate.certificate_id, "reason": "legacy unsigned"}
    ]

    loaded = LineageProof.from_dict(data)
    result = verify_lineage_proof(
        loaded,
        trusted_roots=trusted_roots,
        requested_capability="chat",
        anchor_backend=backend,
    )

    assert isinstance(loaded.revocation_events[0], dict)
    assert not isinstance(loaded.revocation_events[0], RevocationEventV1)
    assert result.ok is False
    assert result.status == "invalid"
    assert "revocation event is malformed" in result.errors[0]
