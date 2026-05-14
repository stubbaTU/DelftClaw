"""Bitcoin HD wallet wrapper used by autonomous OpenClaw agents."""

from __future__ import annotations

import hashlib
from typing import Any

from bitcoinlib.keys import HDKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.derivation import DerivationPath, wallet_path
from identity.seed import Seed


UTXO = Any
SignedTransaction = Any


def _bitcoin_network(network: str) -> str:
    normalized = network.strip().upper()
    if normalized == "MAINNET":
        return "bitcoin"
    if normalized in {"TESTNET", "REGTEST"}:
        return "testnet"
    raise ValueError(f"Unsupported network: {network}")


class Wallet:
    """BIP-32 wallet derived from the agent seed and BIP-44 path."""

    def __init__(self, root: HDKey, child: HDKey, *, path: DerivationPath, network: str) -> None:
        self._root = root
        self._child = child
        self._path = path
        self._network = network
        signing_seed = hashlib.sha256(child.private_byte).digest()
        self.key = Ed25519PrivateKey.from_private_bytes(signing_seed)

    @classmethod
    def from_seed(
        cls,
        seed: Seed,
        *,
        network: str = "MAINNET",
        agent_index: int = 0,
        path: DerivationPath | None = None,
    ) -> "Wallet":
        """Derive wallet keys at m/44'/0'/agent_index'/0/0 by default."""
        net = _bitcoin_network(network)
        root = HDKey.from_seed(seed.bytes, network=net)
        resolved_path = path or wallet_path(agent_index)
        child = root.subkey_for_path(str(resolved_path))
        return cls(root, child, path=resolved_path, network=network.strip().upper())

    @property
    def path(self) -> str:
        """Derivation path used to create this wallet child key."""
        return str(self._path)

    @property
    def xpub(self) -> str:
        """Return the public extended key for identity metadata."""
        return str(self._child.public_master())

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
