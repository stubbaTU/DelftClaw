"""Bitcoin payment composition (sender) and verification (receiver)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import msgpack
from coincurve import PrivateKey, PublicKey

from identity.wallet import UTXO, Wallet
from shared.envelopes import BTCPayload
from shared.ids import Nonce


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


@dataclass(frozen=True)
class SignedPaymentPayload:
    """Application-layer signed payment claim per PROJECT_DESIGN §7.15.

    Orthogonal to ``BTCPayload.signed_tx`` (the on-chain tx signature). This is the
    secp256k1 signature over a canonical ``(amount, recipient_btc_pubkey, sender_did,
    recipient_did, nonce, ts)`` tuple that lets a receiver export a "DID A paid DID B"
    claim for off-protocol auditing.
    """

    btc: BTCPayload
    sender_did: bytes
    recipient_did: bytes
    nonce: Nonce
    ts: int
    app_signature: bytes


class PaymentSigner:
    """Sign / verify ``SignedPaymentPayload`` with a secp256k1 key (coincurve)."""

    @staticmethod
    def _canonical(
        btc: BTCPayload,
        sender_did: bytes,
        recipient_did: bytes,
        nonce: Nonce,
        ts: int,
    ) -> bytes:
        return msgpack.packb(
            (
                btc.amount_sats,
                btc.recipient_btc_pubkey,
                sender_did,
                recipient_did,
                nonce.to_bytes(),
                ts,
            ),
            use_bin_type=True,
        )

    @staticmethod
    def sign(
        btc: BTCPayload,
        sender_did: bytes,
        recipient_did: bytes,
        nonce: Nonce,
        ts: int,
        secp_priv: bytes,
    ) -> SignedPaymentPayload:
        canonical = PaymentSigner._canonical(btc, sender_did, recipient_did, nonce, ts)
        sig = PrivateKey(secp_priv).sign(canonical)
        return SignedPaymentPayload(
            btc=btc,
            sender_did=sender_did,
            recipient_did=recipient_did,
            nonce=nonce,
            ts=ts,
            app_signature=sig,
        )

    @staticmethod
    def verify(payload: SignedPaymentPayload, sender_secp_pub: bytes) -> bool:
        canonical = PaymentSigner._canonical(
            payload.btc,
            payload.sender_did,
            payload.recipient_did,
            payload.nonce,
            payload.ts,
        )
        try:
            return PublicKey(sender_secp_pub).verify(payload.app_signature, canonical)
        except Exception:
            return False
