"""The CredentialFormat plug-in protocol: one implementation per VC format."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from shared.credentials import Credential, Presentation, VerifiedCredential


class CredentialFormat(Protocol):
    """Plug-in shape implemented once per VC format (W3C-JWT, SD-JWT, BBS+)."""

    format_id: str

    def issue(
        self,
        signing_key: bytes,
        issuer_did: str,
        subject_pubkey: bytes,
        claims: Mapping[str, Any],
    ) -> Credential:
        # Produce a freshly signed Credential in this format.
        ...

    def verify(self, presentation: Presentation) -> VerifiedCredential:
        # Verify issuer signature, holder binding, audience, expiry, schema; raise CredentialInvalid on failure.
        ...
