"""Builds Presentations the holder sends at join time."""

from __future__ import annotations

from identity.agent_identity import AgentIdentity
from shared.credentials import Presentation
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
        # Hold the credential store, format plugin, and our identity for holder signing.
        ...

    def present(
        self,
        vc_id: CredentialId,
        audience: AgentId,
        nonce: Nonce,
    ) -> Presentation:
        # Fetch the VC, sign holder-binding bytes covering (audience, nonce), wrap in Presentation.
        ...
