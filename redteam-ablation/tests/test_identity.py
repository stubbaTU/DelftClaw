"""Ed25519 identity adapter: reporter_id binding and sign/verify round-trip."""

import hashlib

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from redteam_ablation.primitives.identity import Ed25519Identity


def test_public_key_is_32_raw_bytes():
    identity = Ed25519Identity()
    assert isinstance(identity.public_key, bytes)
    assert len(identity.public_key) == 32


def test_reporter_id_matches_sha256_of_pubkey_plus_network():
    identity = Ed25519Identity(network="TESTNET")
    expected = hashlib.sha256(
        identity.public_key + b"TESTNET"
    ).hexdigest()
    assert identity.reporter_id == expected


def test_default_network_is_mainnet():
    identity = Ed25519Identity()
    assert identity.network == "MAINNET"


def test_sign_returns_64_byte_signature():
    identity = Ed25519Identity()
    sig = identity.sign(b"hello world")
    assert isinstance(sig, bytes)
    assert len(sig) == 64


def test_sign_verify_round_trips_with_cryptography():
    identity = Ed25519Identity()
    data = b"the quick brown fox"
    sig = identity.sign(data)
    # Verify externally using the raw public key, proving the adapter signs
    # with the key behind .public_key.
    Ed25519PublicKey.from_public_bytes(identity.public_key).verify(sig, data)


def test_verify_rejects_tampered_data():
    identity = Ed25519Identity()
    sig = identity.sign(b"original")
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(identity.public_key).verify(
            sig, b"tampered"
        )


def test_accepts_supplied_private_key():
    key = Ed25519PrivateKey.generate()
    identity = Ed25519Identity(private_key=key)
    expected_pub = key.public_key().public_bytes_raw()
    assert identity.public_key == expected_pub
