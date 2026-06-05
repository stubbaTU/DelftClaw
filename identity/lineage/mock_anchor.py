"""Default fake Bitcoin-style lineage anchor backend."""

from __future__ import annotations

import hashlib
from dataclasses import replace

from identity.lineage.certificates import utc_now_iso
from identity.lineage.models import AnchorRecord, CertificateBatch, VerificationResult


class MockAnchorBackend:
    """In-memory mock anchor backend.

    This backend verifies fake Bitcoin-style records only. It does not
    inspect Bitcoin transactions, wallets, funding sources, or block headers.
    """

    def __init__(self, *, confirmations: int = 6, start_height: int = 1) -> None:
        self.confirmations = confirmations
        self._height = start_height
        self._records: dict[str, AnchorRecord] = {}

    def create_anchor(self, batch: CertificateBatch) -> AnchorRecord:
        seed = f"{batch.batch_id}|{batch.merkle_root}|{len(self._records)}".encode("utf-8")
        anchor_id = "mock-" + hashlib.sha256(seed).hexdigest()[:24]
        txid = hashlib.sha256(b"DEAI_MOCK_TX\x00" + seed).hexdigest()
        record = AnchorRecord(
            backend="mock",
            anchor_id=anchor_id,
            batch_id=batch.batch_id,
            merkle_root=batch.merkle_root,
            created_at=utc_now_iso(),
            btc_network="mock",
            txid=txid,
            block_height=self._height,
            confirmations=self.confirmations,
        )
        self._records[anchor_id] = record
        self._height += 1
        return record

    def get_anchor(self, anchor_id: str) -> AnchorRecord | None:
        return self._records.get(anchor_id)

    def set_confirmations(self, anchor_id: str, confirmations: int) -> None:
        record = self._records[anchor_id]
        updated = replace(record, confirmations=confirmations)
        self._records[anchor_id] = updated

    def verify_anchor(
        self,
        anchor_record: AnchorRecord,
        merkle_root: str,
        min_confirmations: int,
    ) -> VerificationResult:
        errors: list[str] = []
        stored = self._records.get(anchor_record.anchor_id)
        if stored is not None and stored != anchor_record:
            errors.append("anchor record does not match stored mock record")
        if anchor_record.backend != "mock":
            errors.append("anchor backend is not mock")
        if anchor_record.btc_network != "mock":
            errors.append("anchor btc_network is not mock")
        if anchor_record.anchor_id and not anchor_record.txid:
            errors.append("mock anchor has no txid")
        if anchor_record.merkle_root != merkle_root:
            errors.append("anchor Merkle root mismatch")
        if anchor_record.confirmations < min_confirmations:
            return VerificationResult(
                ok=False,
                status="insufficient_confirmations",
                anchor_id=anchor_record.anchor_id,
                confirmations=anchor_record.confirmations,
                errors=errors + ["insufficient anchor confirmations"],
            )
        if errors:
            return VerificationResult(
                ok=False,
                status="unanchored",
                anchor_id=anchor_record.anchor_id,
                confirmations=anchor_record.confirmations,
                errors=errors,
            )
        return VerificationResult(
            ok=True,
            status="valid",
            anchor_id=anchor_record.anchor_id,
            confirmations=anchor_record.confirmations,
        )
