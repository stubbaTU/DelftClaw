"""Versioned JSON-native lineage models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Literal


JsonDict = dict[str, Any]


@dataclass(frozen=True)
class ChildCertificateV1:
    """Parent-signed certificate that authorizes one child agent."""

    family_id: str
    parent_agent_id: str
    parent_authority_pubkey: str
    child_agent_id: str
    child_authority_pubkey: str
    child_operational_pubkey: str
    issued_at: str
    expires_at: str | None
    capabilities: list[str]
    constraints: JsonDict = field(default_factory=dict)
    anchor_policy: JsonDict = field(default_factory=lambda: {"required": True, "min_confirmations": 0})
    certificate_id: str = ""
    parent_signature: str = ""
    version: int = 1

    def to_dict(self) -> JsonDict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: JsonDict) -> "ChildCertificateV1":
        return cls(
            version=int(data.get("version", 1)),
            certificate_id=str(data.get("certificate_id", "")),
            family_id=str(data["family_id"]),
            parent_agent_id=str(data["parent_agent_id"]),
            parent_authority_pubkey=str(data["parent_authority_pubkey"]),
            child_agent_id=str(data["child_agent_id"]),
            child_authority_pubkey=str(data["child_authority_pubkey"]),
            child_operational_pubkey=str(data["child_operational_pubkey"]),
            issued_at=str(data["issued_at"]),
            expires_at=None if data.get("expires_at") is None else str(data["expires_at"]),
            capabilities=[str(item) for item in data.get("capabilities", [])],
            constraints=dict(data.get("constraints", {})),
            anchor_policy=dict(data.get("anchor_policy", {"required": True, "min_confirmations": 0})),
            parent_signature=str(data.get("parent_signature", "")),
        )


@dataclass(frozen=True)
class RevocationEventV1:
    """Signed event that revokes one lineage certificate."""

    certificate_id: str
    family_id: str
    revoked_by_agent_id: str
    revoked_by_pubkey: str
    reason: str
    created_at: str
    event_id: str = ""
    signature: str = ""
    version: int = 1

    def to_dict(self) -> JsonDict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: JsonDict) -> "RevocationEventV1":
        return cls(
            version=int(data.get("version", 1)),
            event_id=str(data.get("event_id", "")),
            certificate_id=str(data["certificate_id"]),
            family_id=str(data["family_id"]),
            revoked_by_agent_id=str(data["revoked_by_agent_id"]),
            revoked_by_pubkey=str(data["revoked_by_pubkey"]),
            reason=str(data.get("reason", "")),
            created_at=str(data["created_at"]),
            signature=str(data.get("signature", "")),
        )


@dataclass(frozen=True)
class MerkleProofStep:
    side: Literal["left", "right"]
    hash: str

    def to_dict(self) -> JsonDict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: JsonDict) -> "MerkleProofStep":
        side = str(data["side"])
        if side not in {"left", "right"}:
            raise ValueError("Merkle proof side must be 'left' or 'right'")
        return cls(side=side, hash=str(data["hash"]))  # type: ignore[arg-type]


@dataclass(frozen=True)
class CertificateBatch:
    batch_id: str
    merkle_root: str
    leaf_hashes: list[str]
    certificate_ids: list[str]
    created_at: str
    version: int = 1

    def to_dict(self) -> JsonDict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: JsonDict) -> "CertificateBatch":
        return cls(
            version=int(data.get("version", 1)),
            batch_id=str(data["batch_id"]),
            merkle_root=str(data["merkle_root"]),
            leaf_hashes=[str(item) for item in data.get("leaf_hashes", [])],
            certificate_ids=[str(item) for item in data.get("certificate_ids", [])],
            created_at=str(data["created_at"]),
        )


@dataclass(frozen=True)
class AnchorRecord:
    backend: str
    anchor_id: str
    batch_id: str
    merkle_root: str
    created_at: str
    btc_network: str = "mock"
    txid: str = ""
    block_height: int = 0
    confirmations: int = 0
    metadata: JsonDict = field(default_factory=lambda: {"op_return_prefix": "DEAI_ANCHOR_V1"})
    version: int = 1

    def to_dict(self) -> JsonDict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: JsonDict) -> "AnchorRecord":
        return cls(
            version=int(data.get("version", 1)),
            backend=str(data["backend"]),
            anchor_id=str(data["anchor_id"]),
            batch_id=str(data["batch_id"]),
            merkle_root=str(data["merkle_root"]),
            created_at=str(data["created_at"]),
            btc_network=str(data.get("btc_network", "mock")),
            txid=str(data.get("txid", "")),
            block_height=int(data.get("block_height", 0)),
            confirmations=int(data.get("confirmations", 0)),
            metadata=dict(data.get("metadata", {"op_return_prefix": "DEAI_ANCHOR_V1"})),
        )


@dataclass(frozen=True)
class LineageProof:
    leaf_certificate: ChildCertificateV1
    chain: list[ChildCertificateV1]
    merkle_leaf_hash: str
    merkle_proof: list[MerkleProofStep]
    merkle_root: str
    anchor_id: str
    anchor_record: AnchorRecord
    revocation_events: list[RevocationEventV1 | JsonDict] = field(default_factory=list)
    version: int = 1

    def to_dict(self) -> JsonDict:
        return {
            "version": self.version,
            "leaf_certificate": self.leaf_certificate.to_dict(),
            "chain": [cert.to_dict() for cert in self.chain],
            "merkle_leaf_hash": self.merkle_leaf_hash,
            "merkle_proof": [step.to_dict() for step in self.merkle_proof],
            "merkle_root": self.merkle_root,
            "anchor_id": self.anchor_id,
            "anchor_record": self.anchor_record.to_dict(),
            "revocation_events": [to_json_dict(event) for event in self.revocation_events],
        }

    @classmethod
    def from_dict(cls, data: JsonDict) -> "LineageProof":
        revocation_events: list[RevocationEventV1 | JsonDict] = []
        for item in data.get("revocation_events", []):
            raw_event = dict(item)
            try:
                revocation_events.append(RevocationEventV1.from_dict(raw_event))
            except (KeyError, TypeError, ValueError):
                revocation_events.append(raw_event)

        return cls(
            version=int(data.get("version", 1)),
            leaf_certificate=ChildCertificateV1.from_dict(dict(data["leaf_certificate"])),
            chain=[ChildCertificateV1.from_dict(dict(item)) for item in data.get("chain", [])],
            merkle_leaf_hash=str(data["merkle_leaf_hash"]),
            merkle_proof=[MerkleProofStep.from_dict(dict(item)) for item in data.get("merkle_proof", [])],
            merkle_root=str(data["merkle_root"]),
            anchor_id=str(data["anchor_id"]),
            anchor_record=AnchorRecord.from_dict(dict(data["anchor_record"])),
            revocation_events=revocation_events,
        )


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    status: str
    subject_agent_id: str = ""
    trusted_root_agent_id: str = ""
    certificate_id: str = ""
    verified_at: str = ""
    anchor_id: str | None = None
    confirmations: int = 0
    capabilities: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> JsonDict:
        return asdict(self)


def to_json_dict(value: Any) -> JsonDict:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return dict(value)
    raise TypeError(f"cannot convert {type(value).__name__} to dict")
