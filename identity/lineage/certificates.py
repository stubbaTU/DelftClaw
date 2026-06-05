"""Certificate issuance and verification primitives."""

from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timezone
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from identity.lineage.canonical import canonical_json_bytes, certificate_body, certificate_body_hash
from identity.lineage.models import ChildCertificateV1


SIGNATURE_DOMAIN = b"DEAI_CHILD_CERTIFICATE_V1\x00"


class SigningKey(Protocol):
    def sign(self, data: bytes) -> bytes:
        ...


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def decode_public_key(value: str) -> bytes:
    text = value.strip()
    try:
        return bytes.fromhex(text)
    except ValueError:
        return base64.b64decode(text, validate=True)


def certificate_signing_payload(certificate: ChildCertificateV1) -> bytes:
    return SIGNATURE_DOMAIN + canonical_json_bytes(certificate_body(certificate))


def issue_child_certificate(
    *,
    parent_signing_key: SigningKey,
    family_id: str,
    parent_agent_id: str,
    parent_authority_pubkey: str,
    child_agent_id: str,
    child_authority_pubkey: str,
    child_operational_pubkey: str,
    issued_at: str | None = None,
    expires_at: str | None = None,
    capabilities: list[str] | None = None,
    constraints: dict[str, object] | None = None,
    anchor_policy: dict[str, object] | None = None,
) -> ChildCertificateV1:
    """Issue a parent-signed child certificate.

    The certificate id is the SHA-256 hash of the unsigned canonical body.
    The parent signature covers the same body with a lineage-specific domain.
    """

    certificate = ChildCertificateV1(
        family_id=family_id,
        parent_agent_id=parent_agent_id,
        parent_authority_pubkey=parent_authority_pubkey,
        child_agent_id=child_agent_id,
        child_authority_pubkey=child_authority_pubkey,
        child_operational_pubkey=child_operational_pubkey,
        issued_at=issued_at or utc_now_iso(),
        expires_at=expires_at,
        capabilities=sorted(set(capabilities or [])),
        constraints=dict(constraints or {}),
        anchor_policy=dict(anchor_policy or {"required": True, "min_confirmations": 0}),
    )
    certificate_id = certificate_body_hash(certificate)
    signed = replace(certificate, certificate_id=certificate_id)
    signature = parent_signing_key.sign(certificate_signing_payload(signed))
    return replace(signed, parent_signature=base64.b64encode(signature).decode("ascii"))


def verify_certificate_id(certificate: ChildCertificateV1) -> bool:
    return certificate.certificate_id == certificate_body_hash(certificate)


def verify_certificate_signature(certificate: ChildCertificateV1) -> bool:
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(decode_public_key(certificate.parent_authority_pubkey))
        signature = base64.b64decode(certificate.parent_signature, validate=True)
        pubkey.verify(signature, certificate_signing_payload(certificate))
        return True
    except (InvalidSignature, ValueError):
        return False


def is_certificate_expired(certificate: ChildCertificateV1, *, now: datetime | None = None) -> bool:
    if certificate.expires_at is None:
        return False
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return current > _parse_time(certificate.expires_at)


def certificate_valid_at(certificate: ChildCertificateV1, *, now: datetime | None = None) -> bool:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    issued_at = _parse_time(certificate.issued_at)
    return issued_at <= current and not is_certificate_expired(certificate, now=current)


def certificate_allows_capability(certificate: ChildCertificateV1, capability: str | None) -> bool:
    if capability is None:
        return True
    return capability in set(certificate.capabilities)
