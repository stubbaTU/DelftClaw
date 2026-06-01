from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass


_HEX_TXID = re.compile(r"^[0-9a-fA-F]{64}$")
_MOCK_TXID = re.compile(r"^(mock|demo|tx|regtest)[-_][A-Za-z0-9._:\-]+$")


@dataclass(frozen=True)
class BitcoinAnchor:
    """Deterministic donation anchor used as the money root of trust.

    This intentionally does not query Bitcoin Core or a block explorer. It
    records whether the supplied transaction reference is shaped like durable
    chain evidence, so experiments can distinguish verified-looking anchors
    from local smoke-test placeholders.
    """

    txid: str
    donation_address: str
    amount_sats: int
    seedbox_id: str
    network: str = "mock"
    confirmations: int = 0
    output_index: int | None = None
    verified: bool = False
    verification_reason: str = ""
    anchor_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class BitcoinAnchorVerifier:
    """Local verifier for Bitcoin-rooted donation evidence."""

    def __init__(self, *, network: str = "mock", min_confirmations: int = 0):
        self.network = network.strip().lower() or "mock"
        self.min_confirmations = max(0, int(min_confirmations))

    def build_anchor(
        self,
        *,
        txid: str,
        donation_address: str,
        amount_sats: int,
        seedbox_id: str,
        confirmations: int = 0,
        output_index: int | None = None,
    ) -> BitcoinAnchor:
        txid = txid.strip()
        donation_address = donation_address.strip()
        amount_sats = int(amount_sats)
        confirmations = int(confirmations)
        verified, reason = self._verify(
            txid=txid,
            donation_address=donation_address,
            amount_sats=amount_sats,
            confirmations=confirmations,
        )
        return BitcoinAnchor(
            txid=txid,
            donation_address=donation_address,
            amount_sats=amount_sats,
            seedbox_id=seedbox_id,
            network=self.network,
            confirmations=confirmations,
            output_index=output_index,
            verified=verified,
            verification_reason=reason,
            anchor_id=self._anchor_id(
                txid=txid,
                donation_address=donation_address,
                amount_sats=amount_sats,
                seedbox_id=seedbox_id,
                output_index=output_index,
            ),
        )

    def _verify(
        self,
        *,
        txid: str,
        donation_address: str,
        amount_sats: int,
        confirmations: int,
    ) -> tuple[bool, str]:
        if not donation_address:
            return False, "missing donation address"
        if amount_sats <= 0:
            return False, "amount_sats must be positive"
        if confirmations < self.min_confirmations:
            return False, "insufficient confirmations"
        if _HEX_TXID.fullmatch(txid):
            return True, "64-hex transaction id"
        if self.network in {"mock", "regtest"} and _MOCK_TXID.fullmatch(txid):
            return True, f"{self.network} experiment transaction id"
        return False, "transaction id is not a Bitcoin txid or accepted local experiment id"

    @staticmethod
    def _anchor_id(
        *,
        txid: str,
        donation_address: str,
        amount_sats: int,
        seedbox_id: str,
        output_index: int | None,
    ) -> str:
        payload = "|".join(
            [
                txid,
                donation_address,
                str(amount_sats),
                seedbox_id,
                "" if output_index is None else str(output_index),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
