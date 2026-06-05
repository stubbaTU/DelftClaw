"""JSON-native lineage tools for the agent tool surface.

These wrappers deliberately stay thin: they assemble inputs for the
``identity.lineage`` primitives, persist through ``LineageStore``, and
return dictionaries suitable for MCP/LLM callers. They do not enable
runtime admission checks or any Bitcoin Core anchoring path.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from agent.runtime import OpenClawAgent
from identity.lineage.canonical import canonical_hash, certificate_hash
from identity.lineage.certificates import issue_child_certificate, utc_now_iso
from identity.lineage.merkle import merkle_proof, merkle_root
from identity.lineage.mock_anchor import MockAnchorBackend
from identity.lineage.models import (
    CertificateBatch,
    ChildCertificateV1,
    LineageProof,
    RevocationEventV1,
)
from identity.lineage.revocation import issue_revocation_event, revocation_feed_version
from identity.lineage.store import LineageStore, read_json, read_jsonl
from identity.lineage.verifier import verify_lineage_proof


JsonDict = dict[str, Any]
ToolSpec = tuple[str, Any, JsonDict, str]


def _authority_pubkey(agent: OpenClawAgent) -> str:
    return agent.identity.app.pubkey.hex()


def _agent_id(agent: OpenClawAgent) -> str:
    return agent.identity.identity_hash


def _trusted_root(agent: OpenClawAgent) -> JsonDict:
    return {"agent_id": _agent_id(agent), "authority_pubkey": _authority_pubkey(agent)}


def _store(agent: OpenClawAgent) -> LineageStore:
    return LineageStore(agent.config.save_dir)


def _lineage_policy(agent: OpenClawAgent) -> JsonDict:
    runtime_status = getattr(agent, "lineage_status", None)
    if isinstance(runtime_status, dict):
        paths = runtime_status.get("paths", {}) if isinstance(runtime_status.get("paths"), dict) else {}
        return {
            "enabled": bool(runtime_status.get("enabled", False)),
            "required": bool(runtime_status.get("required", False)),
            "btc_network": str(runtime_status.get("btc_network", "mock") or "mock"),
            "min_anchor_confirmations": int(runtime_status.get("min_anchor_confirmations", 0)),
            "trusted_roots": [dict(root) for root in runtime_status.get("trusted_roots", [])],
            "accepted_capabilities": list(runtime_status.get("accepted_capabilities", [])),
            "revocation_feed": str(paths.get("revocation_feed") or "lineage/revocations.jsonl"),
        }
    policy = getattr(agent.network_manifest, "lineage", None)
    if policy is None:
        return {
            "enabled": False,
            "required": False,
            "btc_network": "mock",
            "min_anchor_confirmations": 0,
            "trusted_roots": [],
            "accepted_capabilities": [],
            "revocation_feed": "lineage/revocations.jsonl",
        }
    return {
        "enabled": bool(policy.enabled),
        "required": bool(policy.required),
        "btc_network": str(policy.btc_network or "mock"),
        "min_anchor_confirmations": int(policy.min_anchor_confirmations),
        "trusted_roots": [dict(root) for root in policy.trusted_roots],
        "accepted_capabilities": list(policy.accepted_capabilities),
        "revocation_feed": str(policy.revocation_feed),
    }


def _load_certificates(store: LineageStore) -> list[ChildCertificateV1]:
    certificates: list[ChildCertificateV1] = []
    for row in read_jsonl(store.certificates_path):
        certificates.append(ChildCertificateV1.from_dict(row))
    return certificates


def _load_revocations(store: LineageStore) -> list[RevocationEventV1]:
    events: list[RevocationEventV1] = []
    for row in read_jsonl(store.revocations_path):
        events.append(RevocationEventV1.from_dict(row))
    return events


def _find_certificate(store: LineageStore, certificate_id: str) -> ChildCertificateV1 | None:
    for certificate in reversed(_load_certificates(store)):
        if certificate.certificate_id == certificate_id:
            return certificate
    return None


def _birth_package(
    agent: OpenClawAgent,
    proof: LineageProof,
    *,
    trusted_roots: list[JsonDict],
) -> JsonDict:
    store = _store(agent)
    return {
        "version": 1,
        "package_type": "lineage_birth_package_v1",
        "exported_at": utc_now_iso(),
        "lineage_enabled": _lineage_policy(agent)["enabled"],
        "enforced": False,
        "subject_agent_id": proof.leaf_certificate.child_agent_id,
        "certificate_id": proof.leaf_certificate.certificate_id,
        "certificate": proof.leaf_certificate.to_dict(),
        "proof": proof.to_dict(),
        "trusted_roots": trusted_roots,
        "btc_network": "mock",
        "revocation_feed": [event.to_dict() for event in _load_revocations(store)],
        "revocation_feed_path": str(store.revocations_path),
        "cache_path": str(store.cache_path),
    }


def _load_birth_package(store: LineageStore) -> JsonDict | None:
    if not store.birth_package_path.exists():
        return None
    return read_json(store.birth_package_path)


def _coerce_trusted_roots(agent: OpenClawAgent, value: Any) -> list[JsonDict]:
    if value is None:
        return [_trusted_root(agent)]
    if not isinstance(value, list):
        raise ValueError("trusted_roots must be a list")
    roots: list[JsonDict] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("trusted_roots entries must be objects")
        roots.append({
            "agent_id": str(item["agent_id"]),
            "authority_pubkey": str(item["authority_pubkey"]),
        })
    return roots


def _proof_with_local_revocations(proof: LineageProof, store: LineageStore) -> LineageProof:
    events_by_id: dict[str, RevocationEventV1] = {}
    for raw_event in proof.revocation_events:
        try:
            event = RevocationEventV1.from_dict(
                raw_event.to_dict() if hasattr(raw_event, "to_dict") else dict(raw_event)
            )
        except (KeyError, TypeError, ValueError):
            continue
        events_by_id[event.event_id] = event
    for event in _load_revocations(store):
        events_by_id[event.event_id] = event
    return replace(proof, revocation_events=list(events_by_id.values()))


def _lineage_tool_specs(agent: OpenClawAgent) -> list[ToolSpec]:
    async def lineage_status() -> JsonDict:
        """Return local lineage configuration and persistence status."""

        store = _store(agent)
        birth_package = _load_birth_package(store)
        certificates = _load_certificates(store)
        revocations = _load_revocations(store)
        policy = _lineage_policy(agent)
        runtime_status: JsonDict = {}
        try:
            refresh = getattr(agent, "refresh_lineage_status", None)
            if callable(refresh):
                runtime_status = dict(refresh())
        except Exception as exc:
            runtime_status = {
                "status": "unavailable",
                "ok": False,
                "errors": [f"lineage_status_refresh_failed:{type(exc).__name__}: {exc}"],
            }

        status = {
            "enabled": policy["enabled"],
            "required": policy["required"],
            "enforced": False,
            "btc_network": policy["btc_network"] or "mock",
            "default_btc_network": "mock",
            "min_anchor_confirmations": policy["min_anchor_confirmations"],
            "trusted_roots": policy["trusted_roots"],
            "accepted_capabilities": policy["accepted_capabilities"],
            "paths": {
                "root": str(store.root),
                "birth_package": str(store.birth_package_path),
                "certificates": str(store.certificates_path),
                "anchors": str(store.anchors_path),
                "revocations": str(store.revocations_path),
                "cache": str(store.cache_path),
            },
            "certificate_count": len(certificates),
            "revocation_count": len(revocations),
            "latest_certificate_id": birth_package.get("certificate_id", "") if birth_package else "",
        }
        if runtime_status:
            merged_paths = dict(status["paths"])
            merged_paths.update({
                key: value
                for key, value in dict(runtime_status.get("paths", {})).items()
                if value
            })
            status.update(runtime_status)
            status["paths"] = merged_paths
            status["certificate_count"] = len(certificates)
            status["revocation_count"] = len(revocations)
            status["latest_certificate_id"] = str(
                runtime_status.get("certificate_id")
                or (birth_package.get("certificate_id", "") if birth_package else "")
            )
        return status

    async def lineage_issue_child_certificate(
        family_id: str,
        child_agent_id: str,
        child_authority_pubkey: str,
        child_operational_pubkey: str,
        capabilities: list[str] | None = None,
        expires_at: str | None = None,
        constraints: JsonDict | None = None,
        min_anchor_confirmations: int = 0,
        btc_network: str = "mock",
    ) -> JsonDict:
        """Issue and persist a mock-anchored child certificate and proof."""

        if btc_network != "mock":
            return {"error": "unsupported_lineage_btc_network: only 'mock' is implemented"}
        store = _store(agent)
        certificate = issue_child_certificate(
            parent_signing_key=agent.identity.app,
            family_id=family_id,
            parent_agent_id=_agent_id(agent),
            parent_authority_pubkey=_authority_pubkey(agent),
            child_agent_id=child_agent_id,
            child_authority_pubkey=child_authority_pubkey,
            child_operational_pubkey=child_operational_pubkey,
            expires_at=expires_at,
            capabilities=capabilities or [],
            constraints=constraints or {},
            anchor_policy={
                "required": True,
                "min_confirmations": int(min_anchor_confirmations),
            },
        )
        leaf_hashes = [certificate_hash(certificate)]
        root = merkle_root(leaf_hashes)
        batch = CertificateBatch(
            batch_id=canonical_hash({
                "certificate_id": certificate.certificate_id,
                "issued_at": certificate.issued_at,
                "kind": "lineage_certificate_batch_v1",
            }),
            merkle_root=root,
            leaf_hashes=leaf_hashes,
            certificate_ids=[certificate.certificate_id],
            created_at=utc_now_iso(),
        )
        anchor = MockAnchorBackend().create_anchor(batch)
        proof = LineageProof(
            leaf_certificate=certificate,
            chain=[],
            merkle_leaf_hash=leaf_hashes[0],
            merkle_proof=merkle_proof(leaf_hashes, 0),
            merkle_root=root,
            anchor_id=anchor.anchor_id,
            anchor_record=anchor,
        )
        trusted_roots = [_trusted_root(agent)]
        package = _birth_package(agent, proof, trusted_roots=trusted_roots)
        store.append_certificate(certificate)
        store.save_batch(batch)
        store.append_anchor(anchor)
        store.save_birth_package(package)
        return {
            "certificate": certificate.to_dict(),
            "batch": batch.to_dict(),
            "anchor_record": anchor.to_dict(),
            "proof": proof.to_dict(),
            "trusted_roots": trusted_roots,
            "birth_package_path": str(store.birth_package_path),
        }

    async def lineage_verify_proof(
        proof: JsonDict | None = None,
        trusted_roots: list[JsonDict] | None = None,
        requested_capability: str | None = None,
        min_confirmations: int | None = None,
        include_local_revocations: bool = True,
        use_cache: bool = True,
    ) -> JsonDict:
        """Verify a lineage proof using optional local revocation/cache files."""

        store = _store(agent)
        package = _load_birth_package(store)
        proof_data = proof
        if proof_data is None and package is not None:
            proof_data = dict(package["proof"])
        if proof_data is None:
            return {"error": "no_lineage_proof_provided_or_saved"}

        loaded_proof = LineageProof.from_dict(proof_data)
        if include_local_revocations:
            loaded_proof = _proof_with_local_revocations(loaded_proof, store)
        roots_value: Any = trusted_roots
        if roots_value is None and package is not None:
            roots_value = package.get("trusted_roots")
        roots = _coerce_trusted_roots(agent, roots_value)
        result = verify_lineage_proof(
            loaded_proof,
            trusted_roots=roots,  # type: ignore[arg-type]
            requested_capability=requested_capability,
            min_confirmations=min_confirmations,
            cache=store.cache_path if use_cache else None,
        )
        return result.to_dict()

    async def lineage_revoke_certificate(certificate_id: str, reason: str = "") -> JsonDict:
        """Issue and persist a signed revocation event for a local certificate."""

        store = _store(agent)
        certificate = _find_certificate(store, certificate_id)
        if certificate is None:
            return {"error": f"certificate_not_found:{certificate_id}"}
        event = issue_revocation_event(
            revoker_signing_key=agent.identity.app,
            certificate_id=certificate.certificate_id,
            family_id=certificate.family_id,
            revoked_by_agent_id=_agent_id(agent),
            revoked_by_pubkey=_authority_pubkey(agent),
            reason=reason,
        )
        store.append_revocation(event)
        return event.to_dict()

    async def lineage_list_revocations(
        certificate_id: str | None = None,
        limit: int = 100,
    ) -> JsonDict:
        """List locally persisted signed revocation events."""

        store = _store(agent)
        events = _load_revocations(store)
        if certificate_id:
            events = [event for event in events if event.certificate_id == certificate_id]
        events = events[-max(0, int(limit)):]
        return {
            "revocations": [event.to_dict() for event in events],
            "count": len(events),
            "feed_version": revocation_feed_version(events),
            "path": str(store.revocations_path),
        }

    async def lineage_export_birth_package(certificate_id: str | None = None) -> JsonDict:
        """Return the latest saved birth package with current local revocations."""

        store = _store(agent)
        package = _load_birth_package(store)
        if package is None:
            return {"error": "birth_package_not_found"}
        if certificate_id and package.get("certificate_id") != certificate_id:
            return {"error": f"birth_package_not_found:{certificate_id}"}
        proof = _proof_with_local_revocations(LineageProof.from_dict(dict(package["proof"])), store)
        roots = _coerce_trusted_roots(agent, package.get("trusted_roots"))
        exported = _birth_package(agent, proof, trusted_roots=roots)
        return {
            "path": str(store.birth_package_path),
            "package": exported,
        }

    p_none = {"type": "object", "properties": {}, "additionalProperties": False}
    trusted_roots_schema: JsonDict = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "authority_pubkey": {"type": "string"},
            },
            "required": ["agent_id", "authority_pubkey"],
            "additionalProperties": False,
        },
    }

    return [
        (
            "lineage_status",
            lineage_status,
            p_none,
            "Return local lineage status, paths, counts, and explicit disabled/enforced flags.",
        ),
        (
            "lineage_issue_child_certificate",
            lineage_issue_child_certificate,
            {
                "type": "object",
                "properties": {
                    "family_id": {"type": "string"},
                    "child_agent_id": {"type": "string"},
                    "child_authority_pubkey": {"type": "string"},
                    "child_operational_pubkey": {"type": "string"},
                    "capabilities": {"type": "array", "items": {"type": "string"}, "default": []},
                    "expires_at": {"type": "string"},
                    "constraints": {"type": "object", "default": {}},
                    "min_anchor_confirmations": {"type": "integer", "minimum": 0, "default": 0},
                    "btc_network": {"type": "string", "enum": ["mock"], "default": "mock"},
                },
                "required": [
                    "family_id",
                    "child_agent_id",
                    "child_authority_pubkey",
                    "child_operational_pubkey",
                ],
                "additionalProperties": False,
            },
            "Issue a parent-signed child certificate, mock-anchor it, and save a birth package.",
        ),
        (
            "lineage_verify_proof",
            lineage_verify_proof,
            {
                "type": "object",
                "properties": {
                    "proof": {"type": "object"},
                    "trusted_roots": trusted_roots_schema,
                    "requested_capability": {"type": "string"},
                    "min_confirmations": {"type": "integer", "minimum": 0},
                    "include_local_revocations": {"type": "boolean", "default": True},
                    "use_cache": {"type": "boolean", "default": True},
                },
                "additionalProperties": False,
            },
            "Verify a JSON lineage proof using trusted roots, local revocations, and the JSON cache.",
        ),
        (
            "lineage_revoke_certificate",
            lineage_revoke_certificate,
            {
                "type": "object",
                "properties": {
                    "certificate_id": {"type": "string"},
                    "reason": {"type": "string", "default": ""},
                },
                "required": ["certificate_id"],
                "additionalProperties": False,
            },
            "Issue and append a signed revocation event for a locally stored certificate.",
        ),
        (
            "lineage_list_revocations",
            lineage_list_revocations,
            {
                "type": "object",
                "properties": {
                    "certificate_id": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "additionalProperties": False,
            },
            "List local signed lineage revocation events and the feed version.",
        ),
        (
            "lineage_export_birth_package",
            lineage_export_birth_package,
            {
                "type": "object",
                "properties": {
                    "certificate_id": {"type": "string"},
                },
                "additionalProperties": False,
            },
            "Return the latest saved birth package with current local revocation events.",
        ),
    ]


def build_lineage_tools(agent: OpenClawAgent) -> list[ToolSpec]:
    """Build lineage tool specs for ``agent.tools.build_tools``."""

    return _lineage_tool_specs(agent)
