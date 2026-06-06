"""Deterministic mock-anchored lineage fixture generation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity.lineage.canonical import canonical_hash, certificate_hash
from identity.lineage.certificates import issue_child_certificate
from identity.lineage.merkle import merkle_proof, merkle_root
from identity.lineage.mock_anchor import MockAnchorBackend
from identity.lineage.models import CertificateBatch, ChildCertificateV1, LineageProof


RUNNER_NAME = "functional_correctness"
FIXED_ISSUED_AT = "2026-01-01T00:00:00Z"
FIXED_EXPIRES_AT = "2036-01-01T00:00:00Z"


@dataclass(frozen=True)
class LineageFixture:
    proof: LineageProof
    anchor_backend: MockAnchorBackend
    trusted_roots: list[dict[str, str]]
    batch: CertificateBatch
    trial_seed: str
    authority_keys: list[Ed25519PrivateKey]
    agent_ids: list[str]


def derive_trial_seed(global_seed: int, runner: str, depth: int, trial_index: int) -> str:
    material = f"{global_seed}|{runner}|{depth}|{trial_index}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def deterministic_private_key(seed_material: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(seed_material.encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _agent_id(trial_seed: str, index: int) -> str:
    return f"agent-{index:02d}-{hashlib.sha256(f'{trial_seed}|agent|{index}'.encode('utf-8')).hexdigest()[:16]}"


def _operational_pubkey(trial_seed: str, index: int) -> str:
    return hashlib.sha256(f"{trial_seed}|operational|{index}".encode("utf-8")).hexdigest()


def _batch_created_at(trial_index: int) -> str:
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp()
    created = datetime.fromtimestamp(base + trial_index, tz=timezone.utc)
    return created.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_lineage_fixture(
    *,
    global_seed: int,
    depth: int,
    trial_index: int,
    requested_capability: str,
    min_confirmations: int,
    confirmations: int | None = None,
    runner: str = RUNNER_NAME,
) -> LineageFixture:
    trial_seed = derive_trial_seed(global_seed, runner, depth, trial_index)
    family_id = f"mock-lineage-family-{hashlib.sha256(f'{trial_seed}|family'.encode('utf-8')).hexdigest()[:12]}"
    keys = [deterministic_private_key(f"{trial_seed}|key|{index}") for index in range(depth + 1)]
    agent_ids = [_agent_id(trial_seed, index) for index in range(depth + 1)]

    certificates: list[ChildCertificateV1] = []
    for index in range(1, depth + 1):
        certificate = issue_child_certificate(
            parent_signing_key=keys[index - 1],
            family_id=family_id,
            parent_agent_id=agent_ids[index - 1],
            parent_authority_pubkey=public_key_hex(keys[index - 1]),
            child_agent_id=agent_ids[index],
            child_authority_pubkey=public_key_hex(keys[index]),
            child_operational_pubkey=_operational_pubkey(trial_seed, index),
            issued_at=FIXED_ISSUED_AT,
            expires_at=FIXED_EXPIRES_AT,
            capabilities=[requested_capability],
            constraints={"lineage_depth": depth, "experiment": RUNNER_NAME},
            anchor_policy={"required": True, "min_confirmations": min_confirmations},
        )
        certificates.append(certificate)

    leaf = certificates[-1]
    chain = list(reversed(certificates[:-1]))
    leaf_hash = certificate_hash(leaf)
    leaves = [
        canonical_hash({"kind": "mock_noise_leaf", "side": "left", "trial_seed": trial_seed}),
        leaf_hash,
        canonical_hash({"kind": "mock_noise_leaf", "side": "right", "trial_seed": trial_seed}),
    ]
    root = merkle_root(leaves)
    batch = CertificateBatch(
        batch_id=canonical_hash({
            "kind": "mock_lineage_certificate_batch_v1",
            "lineage_depth": depth,
            "trial_seed": trial_seed,
        }),
        merkle_root=root,
        leaf_hashes=leaves,
        certificate_ids=["mock-noise-left", leaf.certificate_id, "mock-noise-right"],
        created_at=_batch_created_at(trial_index),
    )
    backend = MockAnchorBackend(confirmations=confirmations if confirmations is not None else max(min_confirmations, 1))
    anchor = backend.create_anchor(batch)
    proof = LineageProof(
        leaf_certificate=leaf,
        chain=chain,
        merkle_leaf_hash=leaf_hash,
        merkle_proof=merkle_proof(leaves, 1),
        merkle_root=root,
        anchor_id=anchor.anchor_id,
        anchor_record=anchor,
    )
    trusted_roots = [{"agent_id": agent_ids[0], "authority_pubkey": public_key_hex(keys[0])}]
    return LineageFixture(
        proof=proof,
        anchor_backend=backend,
        trusted_roots=trusted_roots,
        batch=batch,
        trial_seed=trial_seed,
        authority_keys=keys,
        agent_ids=agent_ids,
    )
