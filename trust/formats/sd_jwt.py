"""Selective-disclosure JWT (SD-JWT): holder reveals a subset of claims at presentation time."""

from __future__ import annotations

from typing import Any, Mapping

from shared.credentials import Credential, Presentation, VerifiedCredential
from trust.formats.base import CredentialFormat


class SDJWTFormat(CredentialFormat):
    """SD-JWT: issuer marks selected claims as disclosable; holder unblinds at presentation."""

    format_id = "sd-jwt"

    def issue(
        self,
        signing_key: bytes,
        issuer_did: str,
        subject_pubkey: bytes,
        claims: Mapping[str, Any],
    ) -> Credential:
        # Salt + hash each disclosable claim, embed digests in the JWT body, sign with `signing_key`.
        ...

    def verify(self, presentation: Presentation) -> VerifiedCredential:
        # Verify issuer JWS, check disclosed-claim hashes match digests, bind holder signature.
        ...
