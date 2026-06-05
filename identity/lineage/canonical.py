"""Canonical JSON serialization and stable lineage hashes."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from identity.lineage.models import ChildCertificateV1, to_json_dict


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON-native data deterministically."""

    if not isinstance(value, (dict, list, tuple, str, int, float, bool, type(None))):
        value = to_json_dict(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def canonical_json(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def certificate_body(certificate: ChildCertificateV1 | dict[str, Any]) -> dict[str, Any]:
    data = to_json_dict(certificate) if isinstance(certificate, ChildCertificateV1) else dict(certificate)
    data.pop("certificate_id", None)
    data.pop("parent_signature", None)
    return data


def certificate_body_hash(certificate: ChildCertificateV1 | dict[str, Any]) -> str:
    return canonical_hash(certificate_body(certificate))


def certificate_hash(certificate: ChildCertificateV1 | dict[str, Any]) -> str:
    return canonical_hash(certificate)
