"""High-level LineageProof verification."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, TypedDict

from identity.lineage.anchors import AnchorBackend, get_anchor_backend
from identity.lineage.cache import VerificationResultCache, coerce_verification_cache, make_verification_cache_key
from identity.lineage.canonical import certificate_hash
from identity.lineage.certificates import (
    certificate_allows_capability,
    certificate_valid_at,
    verify_certificate_id,
    verify_certificate_signature,
)
from identity.lineage.merkle import verify_merkle_proof
from identity.lineage.models import ChildCertificateV1, LineageProof, VerificationResult
from identity.lineage.revocation import replay_revocation_feed


class TrustedRoot(TypedDict):
    agent_id: str
    authority_pubkey: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _invalid(
    status: str,
    proof: LineageProof,
    errors: list[str],
    *,
    trusted_root_agent_id: str = "",
    now_iso: str | None = None,
) -> VerificationResult:
    return VerificationResult(
        ok=False,
        status=status,
        subject_agent_id=proof.leaf_certificate.child_agent_id,
        trusted_root_agent_id=trusted_root_agent_id,
        certificate_id=proof.leaf_certificate.certificate_id,
        verified_at=now_iso or _now_iso(),
        anchor_id=proof.anchor_id,
        confirmations=proof.anchor_record.confirmations,
        capabilities=list(proof.leaf_certificate.capabilities),
        errors=errors,
    )


def _trusted_root_match(certificate: ChildCertificateV1, trusted_roots: Iterable[TrustedRoot]) -> TrustedRoot | None:
    for root in trusted_roots:
        if (
            certificate.parent_agent_id == root["agent_id"]
            and certificate.parent_authority_pubkey == root["authority_pubkey"]
        ):
            return root
    return None


def _find_parent_certificate(certificate: ChildCertificateV1, chain: list[ChildCertificateV1]) -> ChildCertificateV1 | None:
    for candidate in chain:
        if (
            candidate.child_agent_id == certificate.parent_agent_id
            and candidate.child_authority_pubkey == certificate.parent_authority_pubkey
        ):
            return candidate
    return None


def _verify_certificate_basics(
    certificate: ChildCertificateV1,
    *,
    requested_capability: str | None,
    now: datetime,
) -> str | None:
    if certificate.version != 1:
        return "unsupported certificate version"
    if not verify_certificate_id(certificate):
        return "certificate id mismatch"
    if not verify_certificate_signature(certificate):
        return "certificate signature is invalid"
    if not certificate_valid_at(certificate, now=now):
        return "certificate is expired or not yet valid"
    if not certificate_allows_capability(certificate, requested_capability):
        return "requested capability is not allowed"
    return None


def verify_lineage_proof(
    proof: LineageProof,
    *,
    trusted_roots: list[TrustedRoot],
    requested_capability: str | None = None,
    anchor_backend: AnchorBackend | None = None,
    min_confirmations: int | None = None,
    now: datetime | None = None,
    cache: VerificationResultCache | str | Path | None = None,
) -> VerificationResult:
    """Verify a complete proof without touching runtime or network flows."""

    verified_at = _now_iso()
    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if not trusted_roots:
        return _invalid("invalid", proof, ["no trusted roots configured"], now_iso=verified_at)

    all_certificates = [proof.leaf_certificate, *proof.chain]
    for certificate in all_certificates:
        error = _verify_certificate_basics(
            certificate,
            requested_capability=requested_capability,
            now=current_time,
        )
        if error:
            status = "expired" if "expired" in error else "invalid"
            return _invalid(status, proof, [error], now_iso=verified_at)

    visited: set[str] = set()
    cursor = proof.leaf_certificate
    trusted_root: TrustedRoot | None = None
    while True:
        if cursor.certificate_id in visited:
            return _invalid("invalid", proof, ["certificate chain contains a cycle"], now_iso=verified_at)
        visited.add(cursor.certificate_id)

        trusted_root = _trusted_root_match(cursor, trusted_roots)
        if trusted_root is not None:
            break

        parent = _find_parent_certificate(cursor, proof.chain)
        if parent is None:
            return _invalid("invalid", proof, ["certificate chain does not reach a trusted root"], now_iso=verified_at)
        cursor = parent

    revocation_replay = replay_revocation_feed(
        proof.revocation_events,
        all_certificates,
        trusted_roots=trusted_roots,
    )

    minimum_confirmations = (
        min_confirmations
        if min_confirmations is not None
        else int(proof.leaf_certificate.anchor_policy.get("min_confirmations", 0))
    )
    verification_cache = coerce_verification_cache(cache)
    cache_key = None
    if verification_cache is not None:
        cache_key = make_verification_cache_key(
            proof,
            requested_capability=requested_capability,
            min_confirmations=minimum_confirmations,
            revocation_feed_version=revocation_replay.feed_version,
            trusted_roots=trusted_roots,
        )
        cached_result = verification_cache.get(cache_key)
        if cached_result is not None:
            return cached_result

    def _cache_and_return(result: VerificationResult) -> VerificationResult:
        if verification_cache is not None and cache_key is not None:
            verification_cache.set(cache_key, result)
        return result

    if revocation_replay.errors:
        return _cache_and_return(_invalid(
            "invalid",
            proof,
            revocation_replay.errors,
            trusted_root_agent_id=trusted_root["agent_id"],
            now_iso=verified_at,
        ))
    for certificate in all_certificates:
        if certificate.certificate_id in revocation_replay.revoked_certificate_ids:
            return _cache_and_return(_invalid(
                "revoked",
                proof,
                [f"certificate revoked: {certificate.certificate_id}"],
                trusted_root_agent_id=trusted_root["agent_id"],
                now_iso=verified_at,
            ))

    leaf_hash = certificate_hash(proof.leaf_certificate)
    if proof.merkle_leaf_hash != leaf_hash:
        return _cache_and_return(
            _invalid("invalid", proof, ["Merkle leaf hash does not match leaf certificate"], now_iso=verified_at)
        )
    if not verify_merkle_proof(
        leaf_hash=proof.merkle_leaf_hash,
        proof=proof.merkle_proof,
        expected_root=proof.merkle_root,
    ):
        return _cache_and_return(_invalid("invalid", proof, ["Merkle proof does not verify"], now_iso=verified_at))

    backend = anchor_backend or get_anchor_backend(proof.anchor_record.btc_network)
    anchor_result = backend.verify_anchor(
        proof.anchor_record,
        proof.merkle_root,
        minimum_confirmations,
    )
    if not anchor_result.ok:
        return _cache_and_return(_invalid(
            anchor_result.status,
            proof,
            list(anchor_result.errors),
            trusted_root_agent_id=trusted_root["agent_id"],
            now_iso=verified_at,
        ))
    if proof.anchor_id != proof.anchor_record.anchor_id:
        return _cache_and_return(
            _invalid("unanchored", proof, ["proof anchor_id does not match anchor record"], now_iso=verified_at)
        )

    return _cache_and_return(VerificationResult(
        ok=True,
        status="valid",
        subject_agent_id=proof.leaf_certificate.child_agent_id,
        trusted_root_agent_id=trusted_root["agent_id"],
        certificate_id=proof.leaf_certificate.certificate_id,
        verified_at=verified_at,
        anchor_id=proof.anchor_id,
        confirmations=proof.anchor_record.confirmations,
        capabilities=list(proof.leaf_certificate.capabilities),
    ))
