"""HD Bitcoin wallet derived at BTC_PATH."""

from __future__ import annotations

from dataclasses import dataclass

from identity.seed import Seed
from shared.ids import Txid

from bitcoinlib.wallets import Wallet as BtcWallet
from bitcoinlib.keys import HDKey
from bitcoinlib.transactions import Transaction
from bitcoinlib.mnemonic import Mnemonic
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
        """
        Initialize the Wallet using a BIP39 mnemonic phrase.
        
        This creates a deterministic wallet, caching it in a local database
        using a SHA-256 hash of the mnemonic for the wallet name. The wallet
        defaults to the m/84'/0'/0'/0/0 derivation path for native segwit.
        """
        self.mnemonic = mnemonic
        wallet_id = hashlib.sha256(self.mnemonic.encode()).hexdigest()[:16]
        wallet_name = f"wallet_{wallet_id}"
        
        try:
            self._wallet = BtcWallet(wallet_name)
        except:
            self._wallet = BtcWallet.create(
                wallet_name,
                keys=self.mnemonic,
                network='bitcoin',
                witness_type='segwit'
            )

    @classmethod
    def from_seed(cls, seed: Seed) -> "Wallet":
        """Derive a Wallet instance directly from a Seed object."""
        mnemonic_phrase = Mnemonic().to_mnemonic(seed.bytes)
        return cls(mnemonic_phrase)

    @property
    def pubkey(self) -> bytes:
        """Return the wallet's compressed secp256k1 public key."""
        return self._wallet.get_key().key_public

    def address(self) -> str:
        """Return the human-readable bech32 address for this wallet."""
        return self._wallet.get_key().address

    def compose_payment(
        self,
        recipient_pubkey: bytes,
        amount_sats: int,
        utxos: list[UTXO],
    ) -> SignedTransaction:
        """
        Build a P2WPKH transaction from the supplied UTXOs, sign it, 
        and return the SignedTransaction.
        """
        recipient_key = HDKey(import_key=recipient_pubkey.hex(), network='bitcoin', witness_type='segwit')
        to_address = recipient_key.address

        t = Transaction(network='bitcoin')
        for u in utxos:
            t.add_input(prev_txid=u.txid, output_n=u.vout, value=u.amount_sats)
            
        t.add_output(amount_sats, to_address)
        
        # Sign with our key
        wallet_key = self._wallet.get_key()
        t.sign([{
            'private': wallet_key.key_private.hex(),
            'public': wallet_key.key_public.hex(),
            'address': wallet_key.address
        }])
        
        return SignedTransaction(raw=t.as_bytes(), txid_hint=Txid(t.txid))

    def verify_counterparty_signature(
        self,
        tx: SignedTransaction,
        expected_pubkey: bytes,
    ) -> bool:
        """
        Confirm a transaction really was signed by the public key the sender claims to control.
        """
        try:
            pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), expected_pubkey)
            pub_key.verify(tx.raw, tx.raw, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False
