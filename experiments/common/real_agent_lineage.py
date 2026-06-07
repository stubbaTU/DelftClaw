"""Shared fixtures for real-runtime lineage admission experiments."""

from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bitcoinlib.mnemonic import Mnemonic

from admission.donation_verifier import DonationVerification
from agent import AgentConfig, LineageRuntimeConfig, OpenClawAgent
from communication.bittorrent import StubBitTorrentService
from experiments.common.fixtures import deterministic_private_key, public_key_hex
from identity.agent_identity import AgentIdentity
from identity.lineage.canonical import canonical_hash, certificate_hash
from identity.lineage.certificates import issue_child_certificate
from identity.lineage.merkle import merkle_proof, merkle_root
from identity.lineage.mock_anchor import MockAnchorBackend
from identity.lineage.models import CertificateBatch, LineageProof
from identity.lineage.revocation import issue_revocation_event
from protocol import StubLLMClient


VALID_FROM = "2026-01-01T00:00:00Z"
VALID_UNTIL = "2036-01-01T00:00:00Z"

ATTACK_CASES = (
    "valid_agent_baseline",
    "tampered_child_certificate",
    "tampered_parent_signature",
    "wrong_trusted_root",
    "broken_merkle_proof",
    "wrong_anchor_record",
    "expired_certificate",
    "missing_required_capability",
    "revoked_child_certificate",
    "unauthorized_revocation_signer",
    "missing_lineage_proof",
    "cloned_agent_identity",
    "replayed_nonce_or_stale_proof",
    "malformed_lineage_proof_payload",
)

EXPECTED_STATUS = {
    "valid_agent_baseline": "valid",
    "tampered_child_certificate": "invalid",
    "tampered_parent_signature": "invalid",
    "wrong_trusted_root": "invalid",
    "broken_merkle_proof": "invalid",
    "wrong_anchor_record": "unanchored",
    "expired_certificate": "expired",
    "missing_required_capability": "invalid",
    "revoked_child_certificate": "revoked",
    "unauthorized_revocation_signer": "invalid",
    "missing_lineage_proof": "missing",
    "cloned_agent_identity": "invalid",
    "replayed_nonce_or_stale_proof": "replay",
    "malformed_lineage_proof_payload": "invalid",
}


class AlwaysAcceptVerifier:
    def verify(self, txid_hex: str) -> DonationVerification:
        return DonationVerification(accepted=True, paid_sats=10_000, confirmations=1)


@dataclass(frozen=True)
class AttackSetup:
    proof: dict[str, Any] | None
    trusted_roots: tuple[dict[str, str], ...]
    accepted_capabilities: tuple[str, ...]
    runtime_identity: AgentIdentity
    proof_supplied: bool
    mutation_target: str
    mutation_strategy: str


def deterministic_identity(
    global_seed: int,
    experiment_name: str,
    attack_case: str,
    trial_index: int,
    role: str,
) -> AgentIdentity:
    material = (
        f"{global_seed}|{experiment_name}|{attack_case}|{trial_index}|{role}"
    ).encode("utf-8")
    entropy = hashlib.sha256(material).digest()[:16]
    mnemonic = Mnemonic().to_mnemonic(entropy)
    return AgentIdentity(network="TESTNET", mnemonic=mnemonic)


def build_runtime_agent(
    identity: AgentIdentity,
    save_dir: Path,
    lineage: LineageRuntimeConfig,
) -> OpenClawAgent:
    return OpenClawAgent(
        identity=identity,
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            address="127.0.0.1",
            save_dir=save_dir,
            btc_network="mock",
            lineage=lineage,
        ),
        bt_service=StubBitTorrentService(save_dir=save_dir),
    )


def authority_pubkey(identity: AgentIdentity) -> str:
    return identity.app.pubkey.hex()


def raw_operational_pubkey(identity: AgentIdentity) -> str:
    return identity.ipv8.raw_pubkey.hex()


def build_proof(
    *,
    root: AgentIdentity,
    subject: AgentIdentity,
    family_id: str,
    capability: str,
    experiment_name: str,
    expires_at: str = VALID_UNTIL,
) -> dict[str, Any]:
    certificate = issue_child_certificate(
        parent_signing_key=root.app.key,
        family_id=family_id,
        parent_agent_id=root.identity_hash,
        parent_authority_pubkey=authority_pubkey(root),
        child_agent_id=subject.identity_hash,
        child_authority_pubkey=authority_pubkey(subject),
        child_operational_pubkey=raw_operational_pubkey(subject),
        issued_at=VALID_FROM,
        expires_at=expires_at,
        capabilities=[capability],
        constraints={"experiment": experiment_name},
        anchor_policy={"required": True, "min_confirmations": 0},
    )
    leaf_hash = certificate_hash(certificate)
    leaves = [
        canonical_hash({"kind": "noise", "side": "left", "family_id": family_id}),
        leaf_hash,
        canonical_hash({"kind": "noise", "side": "right", "family_id": family_id}),
    ]
    root_hash = merkle_root(leaves)
    batch = CertificateBatch(
        batch_id=canonical_hash({
            "kind": "real_agent_adversarial_batch_v1",
            "family_id": family_id,
            "certificate_id": certificate.certificate_id,
        }),
        merkle_root=root_hash,
        leaf_hashes=leaves,
        certificate_ids=["noise-left", certificate.certificate_id, "noise-right"],
        created_at=VALID_FROM,
    )
    anchor = MockAnchorBackend(confirmations=1).create_anchor(batch)
    return LineageProof(
        leaf_certificate=certificate,
        chain=[],
        merkle_leaf_hash=leaf_hash,
        merkle_proof=merkle_proof(leaves, 1),
        merkle_root=root_hash,
        anchor_id=anchor.anchor_id,
        anchor_record=anchor,
    ).to_dict()


def _flip_signature(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def build_attack_setup(
    *,
    config: dict[str, Any],
    experiment_name: str,
    attack_case: str,
    trial_index: int,
    root: AgentIdentity,
    child: AgentIdentity,
) -> AttackSetup:
    if attack_case not in ATTACK_CASES:
        raise ValueError(f"unsupported real-agent attack case: {attack_case}")
    capability = str(config["requested_capability"])
    family_hash = canonical_hash({
        "seed": config["seed"],
        "experiment": experiment_name,
        "attack_case": attack_case,
        "trial_index": trial_index,
    })
    family_id = f"real-agent-family-{family_hash[:16]}"
    proof = build_proof(
        root=root,
        subject=child,
        family_id=family_id,
        capability=capability,
        experiment_name=experiment_name,
    )
    trusted_roots = ({
        "agent_id": root.identity_hash,
        "authority_pubkey": authority_pubkey(root),
    },)
    setup = AttackSetup(
        proof=proof,
        trusted_roots=trusted_roots,
        accepted_capabilities=(capability,),
        runtime_identity=child,
        proof_supplied=True,
        mutation_target="",
        mutation_strategy="none",
    )

    if attack_case == "valid_agent_baseline":
        return setup
    if attack_case == "tampered_child_certificate":
        proof["leaf_certificate"]["child_agent_id"] = f"tampered-{child.identity_hash[:16]}"
        return AttackSetup(
            **{**setup.__dict__,
               "mutation_target": "leaf_certificate.child_agent_id",
               "mutation_strategy": "replace_after_parent_signature"}
        )
    if attack_case == "tampered_parent_signature":
        proof["leaf_certificate"]["parent_signature"] = _flip_signature(
            str(proof["leaf_certificate"]["parent_signature"])
        )
        return AttackSetup(
            **{**setup.__dict__,
               "mutation_target": "leaf_certificate.parent_signature",
               "mutation_strategy": "flip_first_signature_byte"}
        )
    if attack_case == "wrong_trusted_root":
        wrong_key = deterministic_private_key(
            f"{config['seed']}|{experiment_name}|{attack_case}|{trial_index}"
        )
        return AttackSetup(
            **{**setup.__dict__,
               "trusted_roots": ({
                   "agent_id": f"wrong-root-{trial_index}",
                   "authority_pubkey": public_key_hex(wrong_key),
               },),
               "mutation_target": "gatekeeper.trusted_roots",
               "mutation_strategy": "configure_unrelated_trusted_root"}
        )
    if attack_case == "broken_merkle_proof":
        proof["merkle_proof"][0]["hash"] = canonical_hash({
            "attack_case": attack_case,
            "trial_index": trial_index,
        })
        return AttackSetup(
            **{**setup.__dict__,
               "mutation_target": "merkle_proof[0].hash",
               "mutation_strategy": "replace_sibling_hash"}
        )
    if attack_case == "wrong_anchor_record":
        proof["anchor_record"]["merkle_root"] = canonical_hash({
            "attack_case": attack_case,
            "trial_index": trial_index,
            "field": "anchor_record.merkle_root",
        })
        return AttackSetup(
            **{**setup.__dict__,
               "mutation_target": "anchor_record.merkle_root",
               "mutation_strategy": "replace_anchor_root"}
        )
    if attack_case == "expired_certificate":
        expired = build_proof(
            root=root,
            subject=child,
            family_id=family_id,
            capability=capability,
            experiment_name=experiment_name,
            expires_at="2025-01-01T00:00:00Z",
        )
        return AttackSetup(
            **{**setup.__dict__,
               "proof": expired,
               "mutation_target": "leaf_certificate.expires_at",
               "mutation_strategy": "issue_already_expired_certificate"}
        )
    if attack_case == "missing_required_capability":
        return AttackSetup(
            **{**setup.__dict__,
               "accepted_capabilities": (f"missing-{capability}",),
               "mutation_target": "gatekeeper.accepted_capabilities",
               "mutation_strategy": "require_capability_absent_from_certificate"}
        )
    if attack_case in {"revoked_child_certificate", "unauthorized_revocation_signer"}:
        if attack_case == "revoked_child_certificate":
            revoker_key = root.app.key
            revoker_id = root.identity_hash
            revoker_pubkey = authority_pubkey(root)
            strategy = "append_authorized_signed_revocation"
        else:
            revoker_key = deterministic_private_key(
                f"{config['seed']}|{experiment_name}|unauthorized|{trial_index}"
            )
            revoker_id = f"unauthorized-{trial_index}"
            revoker_pubkey = public_key_hex(revoker_key)
            strategy = "append_unrelated_signed_revocation"
        event = issue_revocation_event(
            revoker_signing_key=revoker_key,
            certificate_id=str(proof["leaf_certificate"]["certificate_id"]),
            family_id=str(proof["leaf_certificate"]["family_id"]),
            revoked_by_agent_id=revoker_id,
            revoked_by_pubkey=revoker_pubkey,
            reason=attack_case,
            created_at=VALID_FROM,
        )
        proof["revocation_events"] = [event.to_dict()]
        return AttackSetup(
            **{**setup.__dict__,
               "mutation_target": "revocation_events",
               "mutation_strategy": strategy}
        )
    if attack_case == "missing_lineage_proof":
        return AttackSetup(
            **{**setup.__dict__,
               "proof": None,
               "proof_supplied": False,
               "mutation_target": "lineage_proof_provider",
               "mutation_strategy": "return_none"}
        )
    if attack_case == "cloned_agent_identity":
        victim = deterministic_identity(
            int(config["seed"]), experiment_name, attack_case, trial_index, "victim"
        )
        victim_proof = build_proof(
            root=root,
            subject=victim,
            family_id=family_id,
            capability=capability,
            experiment_name=experiment_name,
        )
        return AttackSetup(
            **{**setup.__dict__,
               "proof": victim_proof,
               "mutation_target": "leaf_certificate.child_operational_pubkey",
               "mutation_strategy": "present_victim_certificate_from_clone_runtime"}
        )
    if attack_case == "replayed_nonce_or_stale_proof":
        return AttackSetup(
            **{**setup.__dict__,
               "mutation_target": "LineageProofPayload.nonce",
               "mutation_strategy": "resend_captured_proof_payload_after_nonce_consumed"}
        )
    if attack_case == "malformed_lineage_proof_payload":
        return AttackSetup(
            **{**setup.__dict__,
               "proof": {"malformed": True},
               "mutation_target": "LineageProofPayload.proof_json",
               "mutation_strategy": "send_json_object_missing_lineage_fields"}
        )
    raise AssertionError("unreachable")


def mode_flags(mode: str) -> tuple[bool, bool]:
    if mode == "disabled":
        return False, False
    if mode == "optional":
        return True, False
    if mode == "required":
        return True, True
    raise ValueError(f"unknown lineage mode: {mode}")


def expected_join_accept(mode: str, attack_case: str) -> bool:
    if mode in {"disabled", "optional"}:
        return True
    return attack_case in {"valid_agent_baseline", "replayed_nonce_or_stale_proof"}


async def wait_for_status(
    agent: OpenClawAgent,
    peer_mid_hex: str,
    *,
    timeout_s: float,
    expected_status: str | None = None,
) -> dict[str, Any] | None:
    deadline = asyncio.get_running_loop().time() + timeout_s
    while asyncio.get_running_loop().time() < deadline:
        status = agent.lineage_peer_status.get(peer_mid_hex)
        if status is not None and (
            expected_status is None or str(status.get("status")) == expected_status
        ):
            return status
        await asyncio.sleep(0.025)
    return None


def first_error(status: dict[str, Any] | None) -> str:
    if not status:
        return ""
    errors = status.get("errors", [])
    return str(errors[0]) if isinstance(errors, list) and errors else ""
