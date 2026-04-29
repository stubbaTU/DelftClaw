"""Bitcoin payment composition (sender) and verification (receiver)."""

from __future__ import annotations

from typing import Protocol

from identity.wallet import UTXO, Wallet
from shared.envelopes import BTCPayload


class UTXOProvider(Protocol):
    """Source of UTXOs the wallet can spend; abstracted so tests can inject synthetic ledgers."""

    def utxos_of(self, pubkey: bytes) -> list[UTXO]:
        # Return spendable UTXOs currently associated with `pubkey`.
        ...


class PaymentBuilder:
    """Composes a BTCPayload using the agent's wallet without broadcasting."""

    def __init__(self, wallet: Wallet, utxo_provider: UTXOProvider) -> None:
        # Hold the wallet and the UTXO source.
        ...

    def compose(self, recipient_pubkey: bytes, amount_sats: int) -> BTCPayload:
        # Gather UTXOs, ask the wallet to build+sign the tx, wrap as BTCPayload (no broadcast).
        ...


class PaymentVerifier:
    """Receiver-side check: confirm the signed tx came from the claimed sender."""

    @staticmethod
    def verify(payload: BTCPayload, expected_sender_btc_pubkey: bytes) -> bool:
        # Parse `payload.signed_tx`, confirm input signatures match the expected sender pubkey.
        ...
