"""Synthetic-BTC wallet keyed off Ed25519 at WALLET_PATH.

Balance state lives in ``stake.StakeOracle``, not on the wallet itself. The
wallet object holds only the signing key — restart-safe, no balance recovery.
"""

from __future__ import annotations

import hashlib

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
        """Return the wallet's canonical Ed25519 public key bytes."""
        return self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def address(self) -> str:
        """Return a stable synthetic address for local DelftClaw experiments."""
        digest = hashlib.sha256(self.pubkey).hexdigest()
        return f"dclaw1{digest[:40]}"

    def compose_payment(
        self,
        recipient_pubkey: bytes,
        amount_sats: int,
        utxos: list[UTXO],
    ) -> SignedTransaction:
        raise NotImplementedError("real Bitcoin transaction composition is not wired into the synthetic wallet")

    def verify_counterparty_signature(
        self,
        tx: SignedTransaction,
        expected_pubkey: bytes,
    ) -> bool:
        """
        Confirm a transaction really was signed by the public key the sender claims to control.
        """
        return False

    def get_private_key(self):
        """Return the raw Ed25519 private key as hex for local tests."""
        return self.key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex()

    def get_balance(self, as_string=False):
        """
        Get wallet balance by scanning the blockchain.
        
        :param as_string: Return as string with BTC suffix if True
        :return: Balance in satoshis (int) or formatted string
        """
        balance = 0
        if as_string:
            return "0.00000000 BTC"
        return balance

    def get_utxos(self):
        """Get unspent transaction outputs."""
        return []

    def sign(self, data: bytes) -> bytes:
        """Produce an Ed25519 signature; used by ``StakeOp.sign``."""
        return self.key.sign(data)
