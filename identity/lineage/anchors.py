"""Anchor backend interface and small registry."""

from __future__ import annotations

from typing import Protocol

from identity.lineage.models import AnchorRecord, CertificateBatch, VerificationResult


class AnchorBackend(Protocol):
    def create_anchor(self, batch: CertificateBatch) -> AnchorRecord:
        ...

    def get_anchor(self, anchor_id: str) -> AnchorRecord | None:
        ...

    def verify_anchor(
        self,
        anchor_record: AnchorRecord,
        merkle_root: str,
        min_confirmations: int,
    ) -> VerificationResult:
        ...


def get_anchor_backend(btc_network: str = "mock") -> AnchorBackend:
    if btc_network == "mock":
        from identity.lineage.mock_anchor import MockAnchorBackend

        return MockAnchorBackend()
    raise ValueError(f"unsupported lineage anchor network: {btc_network}")
