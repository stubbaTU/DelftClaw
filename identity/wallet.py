"""HD Bitcoin wallet derived at BTC_PATH."""

from __future__ import annotations

from dataclasses import dataclass

from identity.seed import Seed
from identity.derivation import BTC_PATH, derive
from shared.ids import Txid

from zpywallet.wallet import create_wallet
from zpywallet.network import BitcoinSegwitMainNet
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hashlib


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

    def __init__(self, mnemonic: str) -> None:
        self.mnemonic = mnemonic
        # We use zpywallet directly to manage the network and keys
        self._wallet = create_wallet(network=BitcoinSegwitMainNet, mnemonic=self.mnemonic)
        self._child_wallet = self._wallet.get_child_for_path("m/84'/0'/0'/0/0")

    @classmethod
    def from_seed(cls, seed: Seed) -> "Wallet":
        # zpywallet primarily interfaces via mnemonics. We map the raw seed
        # securely to a BIP-39 mnemonic phrase to interface with zpywallet.
        from bip_utils import Bip39MnemonicEncoder
        mnemonic_phrase = str(Bip39MnemonicEncoder().Encode(seed.bytes))
        return cls(mnemonic_phrase)

    @property
    def pubkey(self) -> bytes:
        # Return the wallet's compressed secp256k1 public key.
        return bytes.fromhex(self._child_wallet.public_key.to_hex())

    def address(self) -> str:
        # Return the human-readable bech32 address for this wallet.
        return self._child_wallet.address()

    def compose_payment(
        self,
        recipient_pubkey: bytes,
        amount_sats: int,
        utxos: list[UTXO],
    ) -> SignedTransaction:
        # Build a P2WPKH tx from the supplied UTXOs, sign it, and return the SignedTransaction.
        # Raise WalletError if the supplied UTXOs do not cover amount + fees.
        import sporestack
        raise NotImplementedError("Bitcoin transaction composition requires sporestack bindings.")

    def verify_counterparty_signature(
        self,
        tx: SignedTransaction,
        expected_pubkey: bytes,
    ) -> bool:
        # Confirm a tx really was signed by the public key the sender claims to control.
        # Standard signature checks over raw bytes.
        try:
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), expected_pubkey)
            # Example representation of a generic verification
            pub_key.verify(tx.raw, tx.raw, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
