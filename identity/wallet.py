"""Bitcoin HD wallet wrapper used by autonomous OpenClaw agents."""

from __future__ import annotations

import hashlib

from bitcoinlib.keys import HDKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from identity.derivation import DerivationPath, wallet_path
from identity.seed import Seed


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
    def pubkey(self) -> bytes:
        """Compressed secp256k1 public key bytes."""
        return bytes.fromhex(self._child.public_hex)

    @property
    def xpub(self) -> str:
        """Extended public key string for this wallet account."""
        return self._root.public_master().wif()

    @property
    def xpriv(self) -> str:
        """Extended private key string for this wallet account."""
        return self._root.wif_private()

    @property
    def network(self) -> str:
        """Logical OpenClaw network label for this wallet."""
        return self._network

    def address(self) -> str:
        """Legacy P2PKH address (base58) for interoperability."""
        return self._child.address(script_type="p2pkh", encoding="base58")

    def sign(self, msg: bytes) -> bytes:
        """Sign arbitrary bytes using ECDSA-secp256k1 over SHA-256(msg)."""
        digest = hashlib.sha256(msg).digest()
        priv = ec.derive_private_key(int(self._child.private_hex, 16), ec.SECP256K1())
        return priv.sign(digest, ec.ECDSA(hashes.SHA256()))

    def verify(self, msg: bytes, sig: bytes) -> bool:
        """Verify signature produced by :meth:`sign`."""
        digest = hashlib.sha256(msg).digest()
        try:
            pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), self.pubkey)
            pub.verify(sig, digest, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False

    def get_balance(self) -> int:
        """Return on-chain balance in satoshis if available, otherwise 0."""
        try:
            from bitcoinlib.wallets import Wallet as BWallet

            name = f"openclaw_{self.address()}"
            if BWallet.exists(name):
                wallet = BWallet(name)
            else:
                wallet = BWallet.create(name=name, keys=self.xpriv, network=_bitcoin_network(self._network))
            wallet.scan()
            return int(wallet.balance())
        except Exception:
            return 0
