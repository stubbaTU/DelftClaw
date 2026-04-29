"""BBS+ credentials: holder proves predicates over claims in zero knowledge."""

from __future__ import annotations

from typing import Any, Mapping

from shared.credentials import Credential, Presentation, VerifiedCredential
from trust.formats.base import CredentialFormat


class BBSPlusFormat(CredentialFormat):
    """BBS+: issuer signs a vector of messages; holder proves knowledge of a subset in ZK."""

    format_id = "bbs+"

    def issue(
        self,
        signing_key: bytes,
        issuer_did: str,
        subject_pubkey: bytes,
        claims: Mapping[str, Any],
    ) -> Credential:
        # Encode each claim as a message in the BBS+ message vector and sign with the BBS+ key.
        ...

    def verify(self, presentation: Presentation) -> VerifiedCredential:
        # Validate the BBS+ proof of knowledge over the disclosed claims and predicate set.
        ...
