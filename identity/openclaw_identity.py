from __future__ import annotations

import hashlib
from pathlib import Path

from identity.agent_identity import AgentIdentity


class OpenClawIdentity:
    """Compatibility adapter backed by the canonical AgentIdentity bundle."""

    def __init__(self, network: str = "MAINNET", key_path: str | Path | None = None):
        self.network = network.upper()
        identity_network = self.network if self.network in {"MAINNET", "TESTNET", "REGTEST"} else "TESTNET"
        self.key_path = Path(key_path or ".openclaw_identity.json")
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if self.key_path.exists():
            self.agent_identity = AgentIdentity.load(self.key_path)
        else:
            self.agent_identity = AgentIdentity(network=identity_network, agent_index=0)
            self.agent_identity.save(self.key_path)
        if self.agent_identity.network != identity_network:
            self.agent_identity = AgentIdentity(
                network=identity_network,
                agent_index=self.agent_identity.agent_index,
                mnemonic=self.agent_identity.mnemonic,
            )

        self.ipv8 = self.agent_identity.ipv8
        self.public_key = self.agent_identity.ipv8.raw_pubkey
        self.serialized_public_key = self.public_key
        self.identity_hash_bytes = hashlib.sha256(self.public_key + self.network.encode("utf-8")).digest()
        self.identity_hash = self.identity_hash_bytes.hex()

    @property
    def wallet_address(self) -> str:
        return self.agent_identity.wallet.address()

    @property
    def wallet_xpub(self) -> str:
        return self.agent_identity.wallet.xpub

    def public_bundle(self) -> dict[str, str]:
        return self.agent_identity.public_bundle()

    def get_identity_hash(self) -> str:
        return self.identity_hash

    def sign(self, data: bytes) -> bytes:
        return self.agent_identity.ipv8.sign(data)

    @classmethod
    def from_agent_identity(cls, agent_identity: AgentIdentity) -> "OpenClawIdentity":
        """Adapt an in-memory ``AgentIdentity`` into an OpenClawIdentity.

        Bypasses the file-backed ``__init__`` path so callers that already
        hold an ``AgentIdentity`` (derived from a mnemonic or keyfile seed)
        can produce a compatible OpenClawIdentity without writing a JSON
        key file or re-deriving keys.
        """
        instance = cls.__new__(cls)
        instance.network = agent_identity.network.upper()
        instance.key_path = None  # not file-backed
        instance.agent_identity = agent_identity
        instance.ipv8 = agent_identity.ipv8
        instance.public_key = agent_identity.ipv8.raw_pubkey
        instance.serialized_public_key = instance.public_key
        instance.identity_hash_bytes = hashlib.sha256(
            instance.public_key + instance.network.encode("utf-8")
        ).digest()
        instance.identity_hash = instance.identity_hash_bytes.hex()
        return instance

    @staticmethod
    def identity_hash_for_public_key(public_key: bytes, network: str = "MAINNET") -> str:
        tag = network.upper().encode("utf-8")
        return hashlib.sha256(public_key + tag).hexdigest()
