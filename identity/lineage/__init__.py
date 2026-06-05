"""Opt-in secure deAI lineage primitives.

The package is intentionally inert unless callers import and use it.
Runtime admission, IPv8 handshakes, and regtest anchoring remain deferred
until the core proof format is stable.
"""

from identity.lineage.models import (
    AnchorRecord,
    CertificateBatch,
    ChildCertificateV1,
    LineageProof,
    RevocationEventV1,
    VerificationResult,
)
from identity.lineage.cache import VerificationResultCache

__all__ = [
    "AnchorRecord",
    "CertificateBatch",
    "ChildCertificateV1",
    "LineageProof",
    "RevocationEventV1",
    "VerificationResultCache",
    "VerificationResult",
]
