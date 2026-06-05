"""JSON-backed verification result cache for lineage proofs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from identity.lineage.canonical import canonical_hash, certificate_hash
from identity.lineage.models import JsonDict, LineageProof, VerificationResult
from identity.lineage.store import read_json, write_json


CACHE_VERSION = 1


@dataclass(frozen=True)
class VerificationCacheKey:
    """Canonical cache key plus its JSON-native material."""

    key_id: str
    material: JsonDict


def _trusted_roots_material(trusted_roots: Iterable[Mapping[str, str]]) -> list[JsonDict]:
    roots = [
        {
            "agent_id": str(root["agent_id"]),
            "authority_pubkey": str(root["authority_pubkey"]),
        }
        for root in trusted_roots
    ]
    return sorted(roots, key=lambda root: (root["agent_id"], root["authority_pubkey"]))


def make_verification_cache_key(
    proof: LineageProof,
    *,
    requested_capability: str | None,
    min_confirmations: int,
    revocation_feed_version: str,
    trusted_roots: Iterable[Mapping[str, str]],
) -> VerificationCacheKey:
    """Build a stable key for one proof, policy, anchor state, and feed version."""

    proof_material = {
        "version": proof.version,
        "leaf_certificate": proof.leaf_certificate.to_dict(),
        "chain": [certificate.to_dict() for certificate in proof.chain],
        "merkle_leaf_hash": proof.merkle_leaf_hash,
        "merkle_proof": [step.to_dict() for step in proof.merkle_proof],
        "merkle_root": proof.merkle_root,
        "anchor_id": proof.anchor_id,
        "anchor_record": proof.anchor_record.to_dict(),
    }
    material: JsonDict = {
        "version": CACHE_VERSION,
        "certificate_id": proof.leaf_certificate.certificate_id,
        "certificate_hash": certificate_hash(proof.leaf_certificate),
        "chain_certificate_hashes": [certificate_hash(certificate) for certificate in proof.chain],
        "proof_hash": canonical_hash(proof_material),
        "merkle_root": proof.merkle_root,
        "anchor_id": proof.anchor_id,
        "anchor_record_anchor_id": proof.anchor_record.anchor_id,
        "anchor_record_hash": canonical_hash(proof.anchor_record),
        "verification_policy": {
            "requested_capability": requested_capability,
            "min_confirmations": min_confirmations,
            "trusted_roots": _trusted_roots_material(trusted_roots),
        },
        "revocation_feed_version": revocation_feed_version,
    }
    return VerificationCacheKey(key_id=canonical_hash(material), material=material)


def verification_result_from_dict(data: JsonDict) -> VerificationResult:
    return VerificationResult(
        ok=bool(data["ok"]),
        status=str(data["status"]),
        subject_agent_id=str(data.get("subject_agent_id", "")),
        trusted_root_agent_id=str(data.get("trusted_root_agent_id", "")),
        certificate_id=str(data.get("certificate_id", "")),
        verified_at=str(data.get("verified_at", "")),
        anchor_id=None if data.get("anchor_id") is None else str(data.get("anchor_id")),
        confirmations=int(data.get("confirmations", 0)),
        capabilities=[str(item) for item in data.get("capabilities", [])],
        errors=[str(item) for item in data.get("errors", [])],
        warnings=[str(item) for item in data.get("warnings", [])],
    )


class VerificationResultCache:
    """Small JSON file cache for high-level lineage verification results."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _read_cache(self) -> JsonDict:
        if not self.path.exists():
            return {"version": CACHE_VERSION, "entries": {}}
        data = read_json(self.path)
        if int(data.get("version", CACHE_VERSION)) != CACHE_VERSION:
            return {"version": CACHE_VERSION, "entries": {}}
        entries = data.get("entries", {})
        if not isinstance(entries, dict):
            return {"version": CACHE_VERSION, "entries": {}}
        return {"version": CACHE_VERSION, "entries": entries}

    def get(self, key: VerificationCacheKey) -> VerificationResult | None:
        entry = self._read_cache()["entries"].get(key.key_id)
        if not isinstance(entry, dict):
            return None
        if entry.get("key") != key.material:
            return None
        result = entry.get("result")
        if not isinstance(result, dict):
            return None
        return verification_result_from_dict(result)

    def set(self, key: VerificationCacheKey, result: VerificationResult) -> None:
        data = self._read_cache()
        entries = dict(data.get("entries", {}))
        entries[key.key_id] = {
            "version": CACHE_VERSION,
            "key": key.material,
            "result": result.to_dict(),
        }
        write_json(self.path, {"version": CACHE_VERSION, "entries": entries})


def coerce_verification_cache(cache: VerificationResultCache | str | Path | None) -> VerificationResultCache | None:
    if cache is None:
        return None
    if isinstance(cache, VerificationResultCache):
        return cache
    return VerificationResultCache(cache)
