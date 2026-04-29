"""HD Bitcoin wallet derived at BTC_PATH."""

from __future__ import annotations

from dataclasses import dataclass

from identity.seed import Seed
from shared.ids import Txid


@dataclass(frozen=True)
class UTXO:
    """One unspent output the wallet can spend from."""

    txid: Txid
    vout: int
    amount_sats: int
    script_pubkey: bytes


@dataclass(frozen=True)
class SignedTransaction:
    """Raw signed Bitcoin tx ready to hand to a Broadcaster."""

    raw: bytes
    txid_hint: Txid


class Wallet:
    """HD Bitcoin wallet rooted at BTC_PATH (BIP-84 native segwit)."""

    @classmethod
    def from_seed(cls, seed: Seed) -> "Wallet":
        # Derive the privkey at BTC_PATH and construct the wallet.
        ...

    @property
    def pubkey(self) -> bytes:
        # Return the wallet's compressed secp256k1 public key.
        ...

    def address(self) -> str:
        # Return the human-readable bech32 address for this wallet.
        ...

    def compose_payment(
        self,
        recipient_pubkey: bytes,
        amount_sats: int,
        utxos: list[UTXO],
    ) -> SignedTransaction:
        # Build a P2WPKH tx from the supplied UTXOs, sign it, and return the SignedTransaction.
        # Raise WalletError if the supplied UTXOs do not cover amount + fees.
        ...

    def verify_counterparty_signature(
        self,
        tx: SignedTransaction,
        expected_pubkey: bytes,
    ) -> bool:
        # Confirm a tx really was signed by the public key the sender claims to control.
        ...
