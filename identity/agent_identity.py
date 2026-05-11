"""Composite identity bundle for OpenClaw agents."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from identity.app_key import AppSigningKey
from identity.mls_key import MLSSigningKey
from identity.ipv8_key import IPv8KeyPair
from identity.seed import Seed
from identity.wallet import Wallet
from shared.ids import AgentId


_NETWORK_TAGS: dict[str, bytes] = {
    "REGTEST": b"REGTEST",
    "TESTNET": b"TESTNET",
    "MAINNET": b"MAINNET",
}


def _normalize_network(value: str) -> str:
    normalized = value.strip().upper()
    if normalized not in _NETWORK_TAGS:
        raise ValueError("network must be one of REGTEST, TESTNET, MAINNET")
    return normalized


def _fernet_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


class AgentIdentity:
    """Identity bundle containing IPv8, MLS/app signing, and wallet keys."""

    def __init__(
        self,
        network: str = "TESTNET",
        agent_index: int = 0,
        mnemonic: str | None = None,
        *,
        ipv8: IPv8KeyPair | None = None,
        app: AppSigningKey | None = None,
        wallet: Wallet | None = None,
        mls: MLSSigningKey | None = None,
    ) -> None:
        self._network = _normalize_network(network)
        self._agent_index = int(agent_index)
        if self._agent_index < 0:
            raise ValueError("agent_index must be non-negative")

        # Backward-compatible branch for old constructor usage.
        if ipv8 is not None and app is not None and wallet is not None:
            self._mnemonic = mnemonic or ""
            self._ipv8 = ipv8
            self._app = app
            self._wallet = wallet
            self._mls = mls or MLSSigningKey.generate()
            return

        self._mnemonic = mnemonic or Seed.generate_mnemonic(128)
        seed = Seed.from_mnemonic(self._mnemonic)
        self._ipv8 = IPv8KeyPair.from_seed(seed)
        self._app = AppSigningKey.from_seed(seed)
        self._mls = MLSSigningKey.from_seed(seed)
        self._wallet = Wallet.from_seed(seed, network=self._network, agent_index=self._agent_index)

    @classmethod
    def from_seed(cls, seed: Seed, network: str = "TESTNET") -> "AgentIdentity":
        """Compatibility constructor for legacy callers that already hold a Seed."""
        return cls(network=network, agent_index=0, mnemonic=seed.mnemonic)

    @property
    def network(self) -> str:
        """Identity network tag."""
        return self._network

    @property
    def agent_index(self) -> int:
        """BIP-44 account index backing this identity."""
        return self._agent_index

    @property
    def mnemonic(self) -> str:
        """Mnemonic phrase for this identity (secret material)."""
        return self._mnemonic

    @property
    def ipv8(self) -> IPv8KeyPair:
        """IPv8 keypair wrapper."""
        return self._ipv8

    @property
    def app(self) -> AppSigningKey:
        """Application signing key used by communication layer."""
        return self._app

    @property
    def mls(self) -> MLSSigningKey:
        """MLS signing key wrapper."""
        return self._mls

    @property
    def wallet(self) -> Wallet:
        """Bitcoin wallet wrapper."""
        return self._wallet

    @property
    def identity_hash_bytes(self) -> bytes:
        """SHA256(ipv8_public_key_bytes || network_tag)."""
        return hashlib.sha256(self._ipv8.public_key_bytes + _NETWORK_TAGS[self._network]).digest()

    @property
    def identity_hash(self) -> str:
        """Hex encoded network-bound identity hash."""
        return self.identity_hash_bytes.hex()

    def get_identity_hash(self) -> str:
        """Compatibility accessor for integration code expecting method form."""
        return self.identity_hash

    @property
    def agent_id(self) -> AgentId:
        """AgentId wrapper around identity hash bytes."""
        return AgentId.from_pubkey(self.identity_hash_bytes)

    def public_bundle(self) -> dict[str, str]:
        """Return public identity metadata for OpenClaw and MCP tools."""
        return {
            "agent_id": self.identity_hash,
            "ipv8_pubkey": self._ipv8.public_key_bytes.hex(),
            "mls_pubkey": self._mls.public_key_bytes.hex(),
            "wallet_address": self._wallet.address(),
            "wallet_xpub": self._wallet.xpub,
            "network": self._network,
        }

    def save(self, path: str | Path, passphrase: str | None = None) -> None:
        """Persist identity metadata in JSON; encrypt mnemonic when passphrase is provided."""
        payload: dict[str, object] = {
            "network": self._network,
            "agent_index": self._agent_index,
            "encrypted": bool(passphrase),
        }

        if passphrase:
            salt = os.urandom(16)
            token = Fernet(_fernet_key(passphrase, salt)).encrypt(self._mnemonic.encode("utf-8"))
            payload["salt_b64"] = base64.b64encode(salt).decode("ascii")
            payload["mnemonic_token"] = token.decode("ascii")
        else:
            payload["mnemonic"] = self._mnemonic

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path, passphrase: str | None = None) -> "AgentIdentity":
        """Load identity from JSON and re-derive keys from mnemonic."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        network = str(data["network"])
        agent_index = int(data.get("agent_index", 0))
        encrypted = bool(data.get("encrypted", False))

        if encrypted:
            if passphrase is None:
                raise ValueError("passphrase is required to load encrypted identity")
            salt = base64.b64decode(str(data["salt_b64"]))
            token = str(data["mnemonic_token"]).encode("ascii")
            mnemonic = Fernet(_fernet_key(passphrase, salt)).decrypt(token).decode("utf-8")
        else:
            mnemonic = str(data.get("mnemonic", ""))

        return cls(network=network, agent_index=agent_index, mnemonic=mnemonic)
