"""Format-agnostic credential / presentation / key-bundle dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Mapping

from shared.ids import AgentId, Nonce


@dataclass(frozen=True)
class Credential:
    """Neutral, format-agnostic VC representation. The format-specific bytes live in `raw`."""

    format_id: str
    # `format_id` is one of "w3c-jwt", "sd-jwt", "bbs+".
    issuer_pubkey: bytes
    subject_pubkey: bytes
    claims: Mapping[str, Any]
    raw: bytes
    # `raw` is the original signed bytes; verifiers re-parse this to check the signature.


@dataclass(frozen=True)
class Presentation:
    """What a peer hands over at join time to prove possession of a Credential."""

    credential: Credential
    audience: AgentId
    # `audience` is the room host this presentation is bound to; prevents cross-room replay.
    nonce: Nonce
    holder_signature: bytes
    # `holder_signature` proves the presenter holds the subject privkey; covers (audience, nonce).


@dataclass(frozen=True)
class VerifiedCredential:
    """Output of the CredentialVerifier; safe for AdmissionPolicy to act on."""

    credential: Credential
    verified_at: datetime
    revocation_status: Literal["fresh", "unknown"]


@dataclass(frozen=True)
class KeyBundle:
    """Public-key pair a peer publishes so others can authenticate it."""

    ipv8: bytes
    # `ipv8` is the Ed25519 long-term transport-layer key.
    app: bytes
    # `app` is the Ed25519 application-layer signing key (verifies WireFrame sigs).
