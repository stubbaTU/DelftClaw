"""BIP-32 derivation paths and the derive() helper."""

from __future__ import annotations

from identity.seed import Seed


class DerivationPath(str):
    """Newtype wrapping a BIP-32 path string like ``m/44'/0'/0'/0/0``."""

    @classmethod
    def parse(cls, p: str) -> "DerivationPath":
        # Validate the path syntax (segments, hardened markers); raise IdentityError on bad input.
        ...


# Canonical derivation paths fixed across the project. Coin-type 0 is Bitcoin per BIP-44.
IPV8_PATH = DerivationPath("m/44'/0'/0'/0/0")
MLS_PATH = DerivationPath("m/44'/0'/0'/1/0")
BTC_PATH = DerivationPath("m/84'/0'/0'/0/0")
# `BTC_PATH` follows BIP-84 for native segwit (P2WPKH) addresses.

REPLICA_PATH_TEMPLATE = "m/44'/0'/{replica_index}'/0/0"
# Template used by replication.child_seed; the {replica_index} placeholder is replaced per replica.


def derive(seed: Seed, path: DerivationPath) -> bytes:
    # Standard BIP-32 child-key derivation; returns a 32-byte private key for the given path.
    ...
