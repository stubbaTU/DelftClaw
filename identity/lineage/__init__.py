"""Opt-in secure deAI lineage primitives.

The package is intentionally inert unless callers import and use it.
Runtime admission and IPv8 handshake integration remain opt-in through
the agent/runtime and communication layers; regtest anchoring is still
out of this package-local surface.
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
