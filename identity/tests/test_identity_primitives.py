from __future__ import annotations

from pathlib import Path

from identity.agent_identity import AgentIdentity
from identity.seed import Seed


def test_mnemonic_seed_roundtrip() -> None:
    mnemonic = Seed.generate_mnemonic(128)
    a = Seed.from_mnemonic(mnemonic)
    b = Seed.from_mnemonic(mnemonic)
    assert a.bytes == b.bytes


def test_agent_identity_hash_network_binding() -> None:
    mnemonic = Seed.generate_mnemonic(128)
    mainnet = AgentIdentity(network="MAINNET", agent_index=0, mnemonic=mnemonic)
    testnet = AgentIdentity(network="TESTNET", agent_index=0, mnemonic=mnemonic)
    assert mainnet.get_identity_hash() != testnet.get_identity_hash()


def test_agent_identity_save_load(tmp_path: Path) -> None:
    path = tmp_path / "agent_identity.json"
    identity = AgentIdentity(network="REGTEST", agent_index=2)
    identity.save(path)

    loaded = AgentIdentity.load(path)

    assert loaded.get_identity_hash() == identity.get_identity_hash()
    assert loaded.wallet.address() == identity.wallet.address()


def test_agent_identity_save_load_encrypted(tmp_path: Path) -> None:
    path = tmp_path / "agent_identity.enc.json"
    identity = AgentIdentity(network="REGTEST", agent_index=1)
    identity.save(path, passphrase="pw")

    loaded = AgentIdentity.load(path, passphrase="pw")

    assert loaded.get_identity_hash() == identity.get_identity_hash()

