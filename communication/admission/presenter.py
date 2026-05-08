"""Builds Presentations the holder sends at join time."""

from __future__ import annotations

from identity.agent_identity import AgentIdentity
from shared.credentials import Presentation
from shared.errors import CredentialInvalid
from shared.ids import AgentId, CredentialId, Nonce
from shared.logging import get_logger
from stake.proof import StakeProof
from trust.formats.base import CredentialFormat
from trust.store import TrustStore

_log = get_logger("presenter")


class CredentialPresenter:
    """Constructs a Presentation: fetch VC + sign holder-binding to (audience, nonce)."""

    def __init__(
        self,
        store: TrustStore,
        format: CredentialFormat,
        identity: AgentIdentity,
    ) -> None:
        self._store = store
        self._format = format
        self._identity = identity

    def present(
        self,
        vc_id: CredentialId,
        audience: AgentId,
        nonce: Nonce,
        *,
        stake_proof: StakeProof | None = None,
    ) -> Presentation:
        _log.info(
            "presentation_building",
            vc_id=str(vc_id),
            audience=str(audience),
            nonce_prefix=nonce.to_bytes()[:6].hex(),
            with_stake=stake_proof is not None,
        )

        if vc_id not in self._store:
            _log.info("presentation_failed", reason="vc_not_in_store", vc_id=str(vc_id))
            raise CredentialInvalid(f"no credential stored under {vc_id!r}")
        credential = self._store.get(vc_id)
        _log.debug(
            "vc_fetched",
            vc_id=str(vc_id),
            format_id=credential.format_id,
            issuer_pubkey_prefix=credential.issuer_pubkey[:6].hex(),
            subject_pubkey_prefix=credential.subject_pubkey[:6].hex(),
            claim_keys=list(credential.claims.keys()),
        )

        if credential.subject_pubkey != self._identity.app.pubkey:
            _log.info(
                "presentation_failed",
                reason="subject_pubkey_mismatch",
                vc_id=str(vc_id),
            )
            raise CredentialInvalid(
                "credential subject_pubkey does not match holder app key — cannot present"
            )

        signing_payload = audience.to_bytes() + nonce.to_bytes()
        holder_signature = self._identity.app.sign(signing_payload)
        _log.debug(
            "holder_binding_signed",
            payload_len=len(signing_payload),
            signature_prefix=holder_signature[:6].hex(),
        )

        presentation = Presentation(
            credential=credential,
            audience=audience,
            nonce=nonce,
            holder_signature=holder_signature,
            stake_proof=stake_proof,
        )
        _log.info(
            "presentation_built",
            vc_id=str(vc_id),
            format_id=credential.format_id,
            with_stake=stake_proof is not None,
            stake_purpose=stake_proof.purpose if stake_proof else None,
            stake_min_sats=stake_proof.min_sats if stake_proof else None,
        )
        return presentation
