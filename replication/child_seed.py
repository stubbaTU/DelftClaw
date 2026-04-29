"""Deterministic child-seed derivation from a parent BIP-32 seed."""

from __future__ import annotations

from identity.seed import Seed


class ChildSeedDerivation:
    """Derive a child Seed at REPLICA_PATH_TEMPLATE so each replica gets its own key tree."""

    @staticmethod
    def derive(parent: Seed, replica_index: int) -> Seed:
        # Format REPLICA_PATH_TEMPLATE with replica_index, BIP-32 derive, return Seed(child_bytes).
        ...
