"""Format-agnostic credential structures plus simple VC issue/verify helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import TYPE_CHECKING, Any, Literal, Mapping

from shared.ids import AgentId, Nonce

if TYPE_CHECKING:
    from identity.agent_identity import AgentIdentity
    from stake.proof import StakeProof


@dataclass(frozen=True)
class Credential:
    """Neutral, format-agnostic VC representation. The format-specific bytes live in ``raw``."""

    format_id: str
    issuer_pubkey: bytes
    subject_pubkey: bytes
    claims: Mapping[str, Any]
    raw: bytes


@dataclass(frozen=True)
class Presentation:
    """What a peer hands over at join time to prove possession of a Credential."""

    credential: Credential
    audience: AgentId
    nonce: Nonce
    holder_signature: bytes
    stake_proof: "StakeProof | None" = None


@dataclass(frozen=True)
class VerifiedCredential:
    """Output of the CredentialVerifier; safe for AdmissionPolicy to act on."""

    credential: Credential
    verified_at: datetime
    revocation_status: Literal["fresh", "unknown"]


@dataclass(frozen=True)
class KeyBundle:
    """Public-key triple a peer publishes so others can authenticate it."""

    ipv8: bytes
    app: bytes
    wallet: bytes


def issue_credential(identity: "AgentIdentity", claims: dict[str, Any]) -> dict[str, Any]:
    """Issue a minimal VC dict signed by this identity's IPv8 key."""
    payload = {
        "issuer_id": identity.get_identity_hash(),
        "issuer_pubkey": identity.ipv8.public_key_bytes.hex(),
        "claims": dict(claims),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "network": identity.network,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = identity.ipv8.sign(canonical)
    return {
        **payload,
        "signature": signature.hex(),
        "digest": hashlib.sha256(canonical).hexdigest(),
    }


def verify_credential(vc: dict[str, Any], expected_issuer_id: str) -> bool:
    """Verify VC signature and issuer identity binding."""
    try:
        network = str(vc["network"]).upper()
        if network not in {"REGTEST", "TESTNET", "MAINNET"}:
            return False

        issuer_pubkey = bytes.fromhex(str(vc["issuer_pubkey"]))
        derived_issuer_id = hashlib.sha256(issuer_pubkey + network.encode("ascii")).hexdigest()
        if derived_issuer_id != expected_issuer_id:
            return False
        if str(vc["issuer_id"]) != expected_issuer_id:
            return False

        canonical_payload = {
            "issuer_id": vc["issuer_id"],
            "issuer_pubkey": vc["issuer_pubkey"],
            "claims": vc["claims"],
            "issued_at": vc["issued_at"],
            "network": vc["network"],
        }
        canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

        from ipv8.keyvault.crypto import default_eccrypto

        pub = default_eccrypto.key_from_public_bin(issuer_pubkey)
        sig = bytes.fromhex(str(vc["signature"]))
        return bool(pub.verify(sig, canonical))
    except Exception:
        return False
