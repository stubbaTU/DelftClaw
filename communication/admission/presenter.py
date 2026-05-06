"""Builds Presentations the holder sends at join time."""

from __future__ import annotations

from identity.agent_identity import AgentIdentity
from shared.credentials import Presentation
from shared.errors import CredentialInvalid
from shared.ids import AgentId, CredentialId, Nonce
from trust.formats.base import CredentialFormat
from trust.store import TrustStore


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
    ) -> Presentation:
        if vc_id not in self._store:
            raise CredentialInvalid(f"no credential stored under {vc_id!r}")
        credential = self._store.get(vc_id)
        if credential.subject_pubkey != self._identity.app.pubkey:
            raise CredentialInvalid(
                "credential subject_pubkey does not match holder app key — cannot present"
            )
        signing_payload = audience.to_bytes() + nonce.to_bytes()
        holder_signature = self._identity.app.sign(signing_payload)
        return Presentation(
            credential=credential,
            audience=audience,
            nonce=nonce,
            holder_signature=holder_signature,
        )
