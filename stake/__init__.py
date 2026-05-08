"""Synthetic-BTC stake layer: oracle Protocol + in-memory backend + admission proofs."""

from stake.in_memory import InMemoryStakeOracle, StakeError
from stake.oracle import StakeOracle
from stake.proof import StakeProof

__all__ = [
    "StakeOracle",
    "InMemoryStakeOracle",
    "StakeError",
    "StakeProof",
]
