"""Opt-in secure deAI lineage primitives.

The package is intentionally inert unless callers import and use it.
Runtime admission, IPv8 handshakes, MCP tools, and regtest anchoring are
deferred until the core proof format is stable.
"""

from identity.lineage.models import (
    AnchorRecord,
    CertificateBatch,
    ChildCertificateV1,
    LineageProof,
    VerificationResult,
)

__all__ = [
    "AnchorRecord",
    "CertificateBatch",
    "ChildCertificateV1",
    "LineageProof",
    "VerificationResult",
]
