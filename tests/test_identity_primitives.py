from __future__ import annotations

from pathlib import Path

import pytest

from identity.agent_identity import AgentIdentity
from identity.seed import Seed
from identity.wallet import Wallet


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


# ---------------------------------------------------------------------------
# Synthetic wallet balance tracking (declarative initial_balance_sats)
# ---------------------------------------------------------------------------

def _fresh_wallet(initial: int = 0) -> Wallet:
    seed = Seed.from_mnemonic(Seed.generate_mnemonic(128))
    return Wallet.from_seed(seed, network="REGTEST", initial_balance_sats=initial)


def test_wallet_default_balance_is_zero() -> None:
    """Legacy mock: no initial balance, balance_sats always returns 0."""
    w = _fresh_wallet()
    assert w.balance_sats() == 0


def test_wallet_initial_balance_visible_via_balance_sats() -> None:
    w = _fresh_wallet(initial=50_000)
    assert w.balance_sats() == 50_000


def test_wallet_send_decrements_balance() -> None:
    w = _fresh_wallet(initial=50_000)
    txid = w.send("dclaw1somerecipient", 10_000)
    assert isinstance(txid, str) and len(txid) == 64
    assert w.balance_sats() == 40_000


def test_wallet_send_rejects_overspend_with_clear_error() -> None:
    w = _fresh_wallet(initial=10_000)
    with pytest.raises(ValueError, match="insufficient funds"):
        w.send("dclaw1somerecipient", 20_000)
    # Balance untouched after the failed send.
    assert w.balance_sats() == 10_000


def test_wallet_zero_balance_wallet_still_allows_send_for_legacy_callers() -> None:
    """A wallet constructed without an initial balance keeps the legacy
    fire-and-forget mock behaviour — send() always succeeds. Switching
    to the budget-tracking mode is opt-in via initial_balance_sats > 0."""
    w = _fresh_wallet()
    txid = w.send("dclaw1somerecipient", 999_999)
    assert isinstance(txid, str)
    # No budget set, so balance_sats stays floored at 0.
    assert w.balance_sats() == 0


def test_set_initial_balance_resets_spend_counter() -> None:
    """``set_initial_balance`` is the post-construction setter used by
    OpenClawAgent — it both sets the cap and clears any prior spend."""
    w = _fresh_wallet(initial=10_000)
    w.send("dclaw1x", 5_000)
    assert w.balance_sats() == 5_000
    w.set_initial_balance(20_000)
    assert w.balance_sats() == 20_000   # spent counter cleared


# ---------------------------------------------------------------------------
# Ed25519 sign / verify roundtrip (used by community-log entries)
# ---------------------------------------------------------------------------

def test_wallet_sign_verify_roundtrip() -> None:
    """A wallet signs arbitrary bytes; the same wallet's pubkey verifies."""
    w = _fresh_wallet()
    payload = b"donation_intent: 10000 sats"
    sig = w.sign(payload)
    assert isinstance(sig, bytes) and len(sig) == 64   # Ed25519 sig length
    assert Wallet.verify(w.pubkey, payload, sig) is True


def test_wallet_verify_rejects_tampered_payload() -> None:
    w = _fresh_wallet()
    sig = w.sign(b"original payload")
    assert Wallet.verify(w.pubkey, b"original payload", sig) is True
    assert Wallet.verify(w.pubkey, b"tampered payload", sig) is False


def test_wallet_verify_rejects_wrong_pubkey() -> None:
    w_alice = _fresh_wallet()
    w_bob = _fresh_wallet()
    sig = w_alice.sign(b"alice paid bob 10000")
    assert Wallet.verify(w_alice.pubkey, b"alice paid bob 10000", sig) is True
    # Bob's pubkey must not verify Alice's signature, even on the same payload.
    assert Wallet.verify(w_bob.pubkey, b"alice paid bob 10000", sig) is False


def test_wallet_sign_is_deterministic_per_payload() -> None:
    """Ed25519 sigs are deterministic over the same key + same message —
    a useful property for replay-time entry-hash chaining."""
    w = _fresh_wallet()
    sig1 = w.sign(b"determinism check")
    sig2 = w.sign(b"determinism check")
    assert sig1 == sig2


def test_wallet_sign_rejects_non_bytes() -> None:
    import pytest
    w = _fresh_wallet()
    with pytest.raises(TypeError, match="bytes"):
        w.sign("not bytes")  # type: ignore[arg-type]

