"""Verify a Bitcoin txid paid the community seedbox address.

Used by ``SeedboxCommunity`` on the gatekeeper side: a joiner sends a
``JoinRequestPayload(donation_txid)``, the gatekeeper fetches the
transaction via ``bitcoinlib.services.Service`` and checks it paid at
least ``min_sats`` to ``seedbox_address`` with enough confirmations.

The verifier has two modes:

* ``network="testnet"`` / ``"bitcoin"`` — real-bitcoinlib path. Looks
  up the txid via ``bitcoinlib.services.Service``, walks outputs,
  enforces ``min_sats`` + ``min_confirmations``.
* ``network="mock"`` — auto-admit any non-empty txid (paired with
  ``identity.wallet.Wallet`` in synthetic mode, which produces
  deterministic txids without broadcasting). The donation gate is
  *ceremonial* in mock mode and provides NO admission control. Use
  only for demos / CI; flip to ``"testnet"`` for real admission
  verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from bitcoinlib.services.services import Service


MOCK_NETWORK_NAMES = frozenset({
    "mock",
    "synthetic",
    "mock_regtest",
    "mock-regtest",
    "regtest_mock",
    "regtest-mock",
})


@dataclass(frozen=True)
class DonationVerification:
    """Outcome of one donation check."""

    accepted: bool
    reason: str = ""
    paid_sats: int = 0
    confirmations: int = 0


class DonationVerifier:
    """Check that a txid paid >= ``min_sats`` to ``seedbox_address``.

    ``network`` is forwarded to ``bitcoinlib.Service``; "testnet" is the
    research-friendly default (faucet-fundable). Switch to "bitcoin" for
    mainnet.
    """

    def __init__(
        self,
        seedbox_address: str,
        min_sats: int,
        *,
        min_confirmations: int = 1,
        network: str = "mock",
        service: Optional[Service] = None,
    ) -> None:
        self.seedbox_address = seedbox_address
        self.min_sats = min_sats
        self.min_confirmations = min_confirmations
        self._network = network
        # Defer ``Service(...)`` construction until the first verify() call.
        # bitcoinlib probes its provider pool in ``Service.__init__``; on a
        # constrained VPS that probe can stall (TimeoutError on socket recv)
        # and block agent boot. We don't need network access until a peer
        # actually presents a donation txid — and in mock mode we never do.
        self._service = service

    @property
    def network(self) -> str:
        """Logical network mode. ``mock``/``synthetic`` auto-admits."""
        return self._network

    def _is_mock(self) -> bool:
        return self._network.strip().lower() in MOCK_NETWORK_NAMES

    def _get_service(self) -> Service:
        if self._service is None:
            self._service = Service(network=self._network)
        return self._service

    def verify(self, txid: str) -> DonationVerification:
        # Mock mode: auto-admit any non-empty txid. No network call, no
        # provider rotation. Pairs with ``identity.wallet.Wallet.send`` which
        # produces a deterministic synthetic txid without broadcasting.
        if self._is_mock():
            if not txid:
                return DonationVerification(False, "empty_txid")
            return DonationVerification(
                True,
                "mock_auto_admit",
                paid_sats=self.min_sats,
                confirmations=max(self.min_confirmations, 1),
            )

        try:
            tx = self._get_service().gettransaction(txid)
        except Exception as exc:
            return DonationVerification(False, f"fetch_failed:{exc}")
        if tx is None:
            return DonationVerification(False, "tx_not_found")

        confs = getattr(tx, "confirmations", 0) or 0
        if not isinstance(confs, int):
            confs = 0

        for output in (getattr(tx, "outputs", None) or []):
            addr = self._extract_address(output)
            value = getattr(output, "value", None)
            if addr != self.seedbox_address or not isinstance(value, int):
                continue
            if value < self.min_sats:
                return DonationVerification(
                    False,
                    f"insufficient_amount:{value}<{self.min_sats}",
                    paid_sats=value,
                    confirmations=confs,
                )
            if confs < self.min_confirmations:
                return DonationVerification(
                    False,
                    f"insufficient_confirmations:{confs}<{self.min_confirmations}",
                    paid_sats=value,
                    confirmations=confs,
                )
            return DonationVerification(True, "ok", paid_sats=value, confirmations=confs)

        return DonationVerification(False, "no_matching_output", confirmations=confs)

    @staticmethod
    def _extract_address(output: object) -> str | None:
        addr = getattr(output, "address", None)
        if addr:
            return str(addr)
        addrs = getattr(output, "addresses", None)
        if addrs:
            return str(addrs[0])
        return None
