"""Synthetic-BTC wallet keyed off Ed25519 at WALLET_PATH.

Balance state lives in ``stake.StakeOracle``, not on the wallet itself. The
wallet object holds only the signing key — restart-safe, no balance recovery.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.derivation import WALLET_PATH, derive
from identity.seed import Seed


class Wallet:
    """Ed25519 signing key derived at WALLET_PATH; signs synthetic ``StakeOp`` ops."""

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self.key = key

    @classmethod
    def from_seed(cls, seed: Seed) -> "Wallet":
        priv_bytes = derive(seed, WALLET_PATH)
        if len(priv_bytes) == 64:
            priv_bytes = priv_bytes[:32]
        return cls(Ed25519PrivateKey.from_private_bytes(priv_bytes))

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

    def get_private_key(self):
        """Get the private key in WIF format."""
        return self._wallet.get_key().wif

    def get_balance(self, as_string=False):
        """
        Get wallet balance by scanning the blockchain.
        
        :param as_string: Return as string with BTC suffix if True
        :return: Balance in satoshis (int) or formatted string
        """
        self.wallet.scan()
        balance = self.wallet.balance()
        
        if as_string:
            return f"{balance / 100000000:.8f} BTC"
        return balance

    def get_utxos(self):
        """Get unspent transaction outputs."""
        self.wallet.scan()
        return self.wallet.utxos()


        """Return the canonical 32-byte Ed25519 verify key."""
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, data: bytes) -> bytes:
        """Produce an Ed25519 signature; used by ``StakeOp.sign``."""
        return self.key.sign(data)
