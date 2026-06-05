"""Merkle root and inclusion proof helpers for certificate batches."""

from __future__ import annotations

import hashlib

from identity.lineage.models import MerkleProofStep


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_root(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        raise ValueError("cannot build a Merkle root without leaves")
    level = list(leaf_hashes)
    while len(level) > 1:
        next_level: list[str] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(_hash_pair(left, right))
        level = next_level
    return level[0]


def merkle_proof(leaf_hashes: list[str], index: int) -> list[MerkleProofStep]:
    if not leaf_hashes:
        raise ValueError("cannot build a Merkle proof without leaves")
    if index < 0 or index >= len(leaf_hashes):
        raise IndexError("leaf index out of range")

    proof: list[MerkleProofStep] = []
    level = list(leaf_hashes)
    current_index = index
    while len(level) > 1:
        is_right = current_index % 2 == 1
        sibling_index = current_index - 1 if is_right else current_index + 1
        sibling_hash = level[sibling_index] if sibling_index < len(level) else level[current_index]
        proof.append(MerkleProofStep(side="left" if is_right else "right", hash=sibling_hash))

        next_level: list[str] = []
        for pair_index in range(0, len(level), 2):
            left = level[pair_index]
            right = level[pair_index + 1] if pair_index + 1 < len(level) else left
            next_level.append(_hash_pair(left, right))
        level = next_level
        current_index //= 2
    return proof


def verify_merkle_proof(
    *,
    leaf_hash: str,
    proof: list[MerkleProofStep],
    expected_root: str,
) -> bool:
    current = leaf_hash
    try:
        for step in proof:
            if step.side == "left":
                current = _hash_pair(step.hash, current)
            elif step.side == "right":
                current = _hash_pair(current, step.hash)
            else:
                return False
    except ValueError:
        return False
    return current == expected_root
