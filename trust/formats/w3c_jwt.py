"""Standard W3C Verifiable Credential serialised as a JWT (vc-jwt)."""

from __future__ import annotations

from typing import Any, Mapping

from shared.credentials import Credential, Presentation, VerifiedCredential
from trust.formats.base import CredentialFormat


class W3CJWTFormat(CredentialFormat):
    """W3C VC-JWT: full disclosure of all claims, signed by the issuer's JWS key."""

    format_id = "w3c-jwt"

    def issue(
        self,
        signing_key: bytes,
        issuer_did: str,
        subject_pubkey: bytes,
        claims: Mapping[str, Any],
    ) -> Credential:
        # Build the W3C VC JSON shape, wrap it in a JWT, sign with `signing_key`.
        ...

    def verify(self, presentation: Presentation) -> VerifiedCredential:
        # Parse the JWT, check JWS signature against issuer pubkey, validate JSON-LD claim shape.
        ...
