from pathlib import Path

import pytest

from identity.openclaw_identity import OpenClawIdentity


def test_generates_and_persists_local_key_file(tmp_path: Path) -> None:
    key_path = tmp_path / "openclaw_priv.pem"

    identity_a = OpenClawIdentity(network="mainnet", key_path=key_path)

    assert key_path.exists()
    assert key_path.read_text(encoding="utf-8").strip()
    assert identity_a.network == "MAINNET"

    identity_b = OpenClawIdentity(network="MAINNET", key_path=key_path)

    assert identity_a.public_key == identity_b.public_key
    assert identity_a.get_identity_hash() == identity_b.get_identity_hash()
    assert identity_a.identity_hash_bytes == identity_b.identity_hash_bytes


def test_identity_hash_changes_with_network(tmp_path: Path) -> None:
    key_path = tmp_path / "openclaw_priv.pem"

    identity_main = OpenClawIdentity(network="MAINNET", key_path=key_path)
    identity_test = OpenClawIdentity(network="TESTNET", key_path=key_path)

    assert identity_main.get_identity_hash() != identity_test.get_identity_hash()
    assert identity_main.identity_hash != identity_test.identity_hash


def test_corrupt_key_file_raises_value_error(tmp_path: Path) -> None:
    key_path = tmp_path / "openclaw_priv.pem"
    key_path.write_text("not-a-hex-key", encoding="utf-8")

    with pytest.raises(ValueError):
        OpenClawIdentity(network="MAINNET", key_path=key_path)

