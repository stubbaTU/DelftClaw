"""Compatibility identity wrapper used by OpenClaw bridge and redteam primitives."""

from __future__ import annotations

from pathlib import Path

from identity.agent_identity import AgentIdentity


class OpenClawIdentity:
    """Persistent network-bound identity hash and IPv8 key wrapper."""

    def __init__(self, network: str = "MAINNET", key_path: str | Path | None = None) -> None:
        self.network = network.strip().upper()
        self.key_path = Path(key_path) if key_path is not None else Path("openclaw_identity.json")

        if self.key_path.exists():
            try:
                identity = AgentIdentity.load(self.key_path)
            except Exception as exc:
                raise ValueError(f"invalid identity file: {self.key_path}") from exc
            if identity.network != self.network:
                identity = AgentIdentity(network=self.network, agent_index=identity.agent_index, mnemonic=identity.mnemonic)
        else:
            identity = AgentIdentity(network=self.network, agent_index=0)
            identity.save(self.key_path)

        self._identity = identity

    @property
    def public_key(self) -> bytes:
        """Serialized IPv8 public key bytes."""
        return self._identity.ipv8.public_key_bytes

    @property
    def identity_hash(self) -> str:
        """Hex encoded identity hash bound to network tag."""
        return self._identity.identity_hash

    @property
    def identity_hash_bytes(self) -> bytes:
        """Raw identity hash bytes."""
        return self._identity.identity_hash_bytes

    @property
    def ipv8(self):
        """Compatibility access to IPv8 key wrapper."""
        return self._identity.ipv8

    def get_identity_hash(self) -> str:
        """Return identity hash string."""
        return self._identity.identity_hash

