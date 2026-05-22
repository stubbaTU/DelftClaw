from pathlib import Path


def test_setup_regtest_uses_stable_labeled_wallet_addresses() -> None:
    script = Path("deploy/setup_bitcoin_regtest.sh").read_text(encoding="utf-8")

    assert "delftclaw:%s:primary" in script
    assert "getaddressesbylabel" in script
    assert 'BOB_ADDR=$(wallet_labeled_address bob)' in script
    assert 'addr=$(wallet_labeled_address "$wallet_name" 2>/dev/null || echo "ERROR")' in script
    assert 'btc -rpcwallet=bob getnewaddress' not in script
