#!/usr/bin/env python3
"""Quick verification script for Regtest setup.

This script tests all components of the Bitcoin Regtest integration
to ensure they're working correctly on your system.

Usage:
    python verify_regtest_setup.py [--verbose]
"""

import asyncio
import sys
from pathlib import Path

# Add repo to path
sys.path.insert(0, str(Path(__file__).parent))

def print_header(text: str, level: int = 1) -> None:
    """Print formatted header."""
    symbols = ["=", "-", "~"]
    symbol = symbols[min(level - 1, len(symbols) - 1)]
    print(f"\n{symbol * 60}")
    print(f"  {text}")
    print(f"{symbol * 60}")

def print_check(passed: bool, message: str) -> None:
    """Print a check mark or X."""
    symbol = "✓" if passed else "✗"
    color = "\033[92m" if passed else "\033[91m"
    reset = "\033[0m"
    print(f"{color}{symbol}{reset} {message}")

def test_python_env() -> bool:
    """Test Python environment."""
    print_header("Python Environment")

    try:
        import platform
        version = platform.python_version()
        print(f"  Python version: {version}")

        major, minor = sys.version_info[:2]
        if (major, minor) >= (3, 8):
            print_check(True, f"Python 3.{minor} (>= 3.8)")
            return True
        else:
            print_check(False, f"Python 3.{minor} (requires >= 3.8)")
            return False
    except Exception as e:
        print_check(False, f"Failed to check Python: {e}")
        return False

def test_libsodium() -> bool:
    """Test libsodium/PyNaCl."""
    print_header("libsodium & PyNaCl", 2)

    try:
        from agent.libsodium_setup import setup_libsodium
        result = setup_libsodium()
        print_check(result, "libsodium DLL setup")

        if not result:
            return False

        import nacl
        print_check(True, "PyNaCl import")
        return True
    except Exception as e:
        print_check(False, f"libsodium/PyNaCl: {e}")
        return False

def test_imports() -> bool:
    """Test key module imports."""
    print_header("Module Imports", 2)

    modules = [
        ("agent.bitcoin_rpc", "Bitcoin RPC client"),
        ("agent.regtest_wallet", "Regtest wallet"),
        ("agent.bitcoin_tools", "Bitcoin tools"),
        ("identity.wallet", "Identity wallet"),
        ("identity.seed", "Identity seed"),
    ]

    all_ok = True
    for module, description in modules:
        try:
            __import__(module)
            print_check(True, f"{description} ({module})")
        except Exception as e:
            print_check(False, f"{description} ({module}): {e}")
            all_ok = False

    return all_ok

async def test_bitcoin_rpc() -> bool:
    """Test Bitcoin RPC connectivity."""
    print_header("Bitcoin RPC Connection", 2)

    try:
        from agent.bitcoin_rpc import RegtestClient

        client = RegtestClient("http://127.0.0.1:18443")

        # Try to ping
        result = await client._call_rpc("ping")
        print_check(True, "Bitcoin RPC ping (bitcoind running)")
        return True
    except Exception as e:
        error_msg = str(e)
        if "connection" in error_msg.lower() or "refused" in error_msg.lower():
            print_check(False, "Bitcoin RPC connection (bitcoind not running)")
            print("  → Run: bitcoind -regtest -daemon")
            return False
        else:
            print_check(False, f"Bitcoin RPC test: {e}")
            return False

async def test_wallet() -> bool:
    """Test wallet functionality."""
    print_header("Wallet Functionality", 2)

    try:
        from identity.seed import Seed
        from agent.regtest_wallet import RegtestWallet

        # Create a test wallet with standard mnemonic
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed = Seed.from_mnemonic(mnemonic)
        print_check(True, "Seed from mnemonic")

        wallet = RegtestWallet.from_seed(
            seed,
            network="REGTEST",
            rpc_url="http://127.0.0.1:18443",
            wallet_name="test",
        )
        print_check(True, "RegtestWallet creation")

        # Try to get synthetic balance (always works)
        balance = await wallet.balance_sats()
        print_check(True, f"Wallet balance query (synthetic: {balance} sats)")

        # Try to get on-chain balance (may fail if bitcoind not running)
        try:
            onchain = await wallet.balance_sats_onchain()
            print_check(True, f"On-chain balance (RPC: {onchain} sats)")
        except:
            print_check(False, "On-chain balance (bitcoind not running)")

        return True
    except Exception as e:
        print_check(False, f"Wallet test: {e}")
        return False

async def main() -> None:
    """Run all verification tests."""
    print("\n" + "=" * 60)
    print("  Bitcoin Regtest Setup Verification")
    print("=" * 60)

    results = {
        "Python Environment": test_python_env(),
        "libsodium & PyNaCl": test_libsodium(),
        "Module Imports": test_imports(),
    }

    # Run async tests
    results["Bitcoin RPC"] = await test_bitcoin_rpc()
    results["Wallet Functionality"] = await test_wallet()

    # Summary
    print_header("Summary")

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for test_name, result in results.items():
        print_check(result, test_name)

    print(f"\nResult: {passed}/{total} tests passed")

    if passed == total:
        print("\n✓ All tests passed! Your setup is working correctly.")
        print("\nNext steps:")
        print("  1. If bitcoind is not running yet:")
        print("     → bash install_bitcoin_core.sh")
        print("     → bitcoind -regtest -daemon")
        print("  2. Fund test wallets:")
        print("     → python deploy/init_regtest_wallets.py --initial-balance 500000")
        print("  3. Test agent with on-chain transactions:")
        print("     → python -m agent.example_regtest_setup --agent alice --use-regtest")
    elif passed >= (total - 1):
        print("\n⚠ Most tests passed. Bitcoin RPC is not running.")
        print("\nTo enable full Bitcoin integration:")
        print("  1. Install Bitcoin Core: bash install_bitcoin_core.sh")
        print("  2. Start Bitcoin regtest: bitcoind -regtest -daemon")
        print("  3. Verify: bitcoin-cli -regtest ping")
    else:
        print("\n✗ Some tests failed. Check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())

