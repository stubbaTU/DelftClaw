"""Signed revocation event primitives and feed replay."""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from typing import Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from identity.lineage.canonical import canonical_hash, canonical_json_bytes
from identity.lineage.certificates import SigningKey, decode_public_key, utc_now_iso
from identity.lineage.models import ChildCertificateV1, JsonDict, RevocationEventV1, to_json_dict


SIGNATURE_DOMAIN = b"DEAI_REVOCATION_EVENT_V1\x00"


@dataclass(frozen=True)
class RevocationFeedReplay:
    """Result of replaying a revocation feed against known certificates."""

    feed_version: str
    revoked_certificate_ids: set[str]
    accepted_event_ids: list[str]
    errors: list[str]


def revocation_event_body(event: RevocationEventV1 | JsonDict) -> JsonDict:
    data = to_json_dict(event)
    data.pop("event_id", None)
    data.pop("signature", None)
    return data


def revocation_event_body_hash(event: RevocationEventV1 | JsonDict) -> str:
    return canonical_hash(revocation_event_body(event))


def revocation_event_signing_payload(event: RevocationEventV1) -> bytes:
    return SIGNATURE_DOMAIN + canonical_json_bytes(revocation_event_body(event))


def revocation_feed_version(events: Iterable[RevocationEventV1 | JsonDict]) -> str:
    return canonical_hash([to_json_dict(event) for event in events])


def issue_revocation_event(
    *,
    revoker_signing_key: SigningKey,
    certificate_id: str,
    family_id: str,
    revoked_by_agent_id: str,
    revoked_by_pubkey: str,
    reason: str,
    created_at: str | None = None,
) -> RevocationEventV1:
    event = RevocationEventV1(
        certificate_id=certificate_id,
        family_id=family_id,
        revoked_by_agent_id=revoked_by_agent_id,
        revoked_by_pubkey=revoked_by_pubkey,
        reason=reason,
        created_at=created_at or utc_now_iso(),
    )
    event_id = revocation_event_body_hash(event)
    signed = replace(event, event_id=event_id)
    signature = revoker_signing_key.sign(revocation_event_signing_payload(signed))
    return replace(signed, signature=base64.b64encode(signature).decode("ascii"))


def verify_revocation_event_id(event: RevocationEventV1) -> bool:
    return event.event_id == revocation_event_body_hash(event)


def verify_revocation_event_signature(event: RevocationEventV1) -> bool:
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(decode_public_key(event.revoked_by_pubkey))
        signature = base64.b64decode(event.signature, validate=True)
        pubkey.verify(signature, revocation_event_signing_payload(event))
        return True
    except (InvalidSignature, ValueError):
        return False


def _matches_identity(event: RevocationEventV1, *, agent_id: str, authority_pubkey: str) -> bool:
    return event.revoked_by_agent_id == agent_id and event.revoked_by_pubkey == authority_pubkey


def revocation_authority_error(
    event: RevocationEventV1,
    certificate: ChildCertificateV1,
    trusted_roots: Iterable[Mapping[str, str]],
) -> str | None:
    """Return an error if ``event`` is not allowed to revoke ``certificate``."""

    if event.family_id != certificate.family_id:
        return "revocation family_id does not match certificate"
    if event.certificate_id != certificate.certificate_id:
        return "revocation certificate_id does not match certificate"
    if _matches_identity(
        event,
        agent_id=certificate.parent_agent_id,
        authority_pubkey=certificate.parent_authority_pubkey,
    ):
        return None
    if _matches_identity(
        event,
        agent_id=certificate.child_agent_id,
        authority_pubkey=certificate.child_authority_pubkey,
    ):
        return None
    for root in trusted_roots:
        if _matches_identity(event, agent_id=root["agent_id"], authority_pubkey=root["authority_pubkey"]):
            return None
    return "revocation signer is not authorized for certificate"


def replay_revocation_feed(
    events: Iterable[RevocationEventV1 | JsonDict],
    certificates: Iterable[ChildCertificateV1],
    *,
    trusted_roots: Iterable[Mapping[str, str]],
) -> RevocationFeedReplay:
    raw_events = list(events)
    certificate_by_id = {certificate.certificate_id: certificate for certificate in certificates}
    revoked: set[str] = set()
    accepted: list[str] = []
    errors: list[str] = []

    for raw_event in raw_events:
        try:
            event = RevocationEventV1.from_dict(to_json_dict(raw_event))
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"revocation event is malformed: {exc}")
            continue

        if event.version != 1:
            errors.append(f"unsupported revocation event version: {event.version}")
            continue
        if not verify_revocation_event_id(event):
            errors.append(f"revocation event id mismatch: {event.event_id}")
            continue
        if not verify_revocation_event_signature(event):
            errors.append(f"revocation event signature is invalid: {event.event_id}")
            continue

        certificate = certificate_by_id.get(event.certificate_id)
        if certificate is None:
            continue

        authority_error = revocation_authority_error(event, certificate, trusted_roots)
        if authority_error is not None:
            errors.append(f"{authority_error}: {event.event_id}")
            continue

        revoked.add(event.certificate_id)
        accepted.append(event.event_id)

    return RevocationFeedReplay(
        feed_version=revocation_feed_version(raw_events),
        revoked_certificate_ids=revoked,
        accepted_event_ids=accepted,
        errors=errors,
    )
